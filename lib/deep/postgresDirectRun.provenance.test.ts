import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

const mocks = vi.hoisted(() => ({ collect: vi.fn(), decrypt: vi.fn(), readProfile: vi.fn(), insert: vi.fn(), archive: vi.fn(), upsert: vi.fn() }));
const state = vi.hoisted(() => ({ facts: {} as Record<string, unknown> }));
vi.mock("@/lib/crypto", () => ({ decrypt: mocks.decrypt }));
vi.mock("./postgresDirect", async (original) => ({
  ...await original<typeof import("./postgresDirect")>(), collectDirectFacts: mocks.collect,
}));
vi.mock("@/lib/graph/narrative", () => ({ generateNarratives: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const read = () => table === "user_profiles" ? mocks.readProfile() :
    Promise.resolve({ data: table === "graph_facts" ? { facts: state.facts } : [], error: null });
  const query = {
    eq: () => query, is: () => query, maybeSingle: read,
    then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => read().then(resolve, reject),
    in: mocks.archive,
  };
  return {
    select: () => query, update: () => query, insert: mocks.insert,
    upsert: async (row: { facts: Record<string, unknown> }, options: unknown) => {
      const result = await mocks.upsert(row, options);
      if (!result.error) state.facts = row.facts;
      return result;
    },
  };
} }) }));

import { runDirectPostgresScan } from "./postgresDirectRun";
import { PostgresConnectionError } from "./postgresDirect";
import { CollectorShapeError } from "./apiSchemas";

const encrypted = "encrypted-connection-one";
const dsn = "postgres://private-reader:private-password@private-db.example.com/private-db";
const policies = [{ schemaname: "public", tablename: "invoices", policyname: "read", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] }];
const scanTables = [{ name: "invoices", rlsEnabled: true }];
const facts = { policies, scanTables, grants: [] };

beforeEach(() => {
  vi.clearAllMocks();
  state.facts = { advisors: [{ name: "old-advisor" }], unrelatedSnapshot: { projectId: "other-project" } };
  mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: encrypted }, error: null });
  mocks.decrypt.mockReturnValue(dsn);
  mocks.collect.mockResolvedValue(facts);
  mocks.insert.mockResolvedValue({ error: null });
  mocks.archive.mockResolvedValue({ error: null });
  mocks.upsert.mockResolvedValue({ error: null });
});

describe("Step 2C-3-C1: direct-Postgres connection provenance", () => {
  it("persists self-contained facts bound to an opaque encrypted-connection fingerprint", async () => {
    expect(await runDirectPostgresScan("u")).toMatchObject({ ok: true });
    const snapshot = state.facts.directPostgresSnapshot;
    expect(snapshot).toEqual({
      collector: "postgres-direct", authzProvider: "postgres-rls", completeness: "unknown",
      connectionFingerprint: createHash("sha256").update(encrypted).digest("hex"),
      recordedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), policies, scanTables,
    });
    expect(state.facts.advisors).toEqual([{ name: "old-advisor" }]);
    expect(state.facts.unrelatedSnapshot).toEqual({ projectId: "other-project" });
    expect(state.facts.policies).toEqual(policies);
    expect(state.facts._evidence).toMatchObject({ fields: {
      directPostgresSnapshot: { completeness: "unknown", recordedAt: expect.any(String) },
    } });
    expect(mocks.upsert.mock.calls[0][0].user_id).toBe("u");
    expect(mocks.collect).toHaveBeenCalledTimes(1);
    const stored = JSON.stringify(state.facts);
    for (const privateValue of [encrypted, dsn, "private-reader", "private-password", "private-db.example.com"]) {
      expect(stored).not.toContain(privateValue);
    }
  });

  it("replaces the complete transport snapshot on reconnect, without borrowing previous fields", async () => {
    await runDirectPostgresScan("u");
    const first = state.facts.directPostgresSnapshot as { connectionFingerprint: string };
    mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: "encrypted-connection-two" }, error: null });
    mocks.collect.mockResolvedValue({ policies: [], scanTables: [], grants: [] });
    await runDirectPostgresScan("u");
    expect(state.facts.directPostgresSnapshot).toMatchObject({ policies: [], scanTables: [] });
    expect((state.facts.directPostgresSnapshot as { connectionFingerprint: string }).connectionFingerprint).not.toBe(first.connectionFingerprint);
    expect(state.facts.directPostgresSnapshot).not.toHaveProperty("advisors");
    expect(state.facts.directPostgresSnapshot).not.toHaveProperty("repositoryId");
  });

  it.each([null, "", 42])("does not publish provenance for an absent or malformed encrypted connection: %j", async (postgres_dsn_encrypted) => {
    mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted }, error: null });
    expect(await runDirectPostgresScan("u")).toMatchObject({ ok: false, reason: "not_connected" });
    expect(mocks.collect).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it("refuses a profile read error even if the response also includes connection data", async () => {
    mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: encrypted }, error: { message: "private-read-error" } });
    expect(await runDirectPostgresScan("u")).toMatchObject({ ok: false });
    expect(mocks.collect).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it("preserves the old snapshot and findings after a collector failure", async () => {
    state.facts.directPostgresSnapshot = { old: "preserve" };
    mocks.collect.mockRejectedValue(new PostgresConnectionError("Read-only role required", "not_read_only"));
    expect(await runDirectPostgresScan("u")).toMatchObject({ ok: false, reason: "not_read_only" });
    expect(state.facts.directPostgresSnapshot).toEqual({ old: "preserve" });
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.archive).not.toHaveBeenCalled();
    expect(mocks.insert).not.toHaveBeenCalled();
  });

  it("preserves evidence after a policy shape failure", async () => {
    mocks.collect.mockRejectedValue(new CollectorShapeError("policies", ["invalid"]));
    expect(await runDirectPostgresScan("u")).toMatchObject({ ok: false, reason: "shape_mismatch" });
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.archive).not.toHaveBeenCalled();
  });

  it("does not expose a credential or decryption error in logs", async () => {
    mocks.decrypt.mockImplementation(() => { throw new Error(dsn); });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runDirectPostgresScan("u")).toMatchObject({ ok: false, reason: "not_connected" });
      expect(JSON.stringify(log.mock.calls)).not.toContain(dsn);
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.collect).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("preserves the persisted snapshot on returned fact-write errors under the existing fail-soft contract", async () => {
    state.facts.directPostgresSnapshot = { old: "preserve" };
    mocks.upsert.mockResolvedValue({ error: { message: "write unavailable" } });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      // A scan outcome is not a receipt that graph persistence succeeded.
      expect(await runDirectPostgresScan("u")).toMatchObject({ ok: true });
      expect(state.facts.directPostgresSnapshot).toEqual({ old: "preserve" });
      expect(log).toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

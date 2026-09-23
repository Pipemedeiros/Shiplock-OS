import { beforeEach, describe, expect, it, vi } from "vitest";

// The runner collects and hands one result to the monitor worker's fenced
// commit (3F-C2c). Persistence, merge, and retirement semantics are proven in
// the SQL suite; these tests pin what the runner itself sends and withholds.
const mocks = vi.hoisted(() => ({ collect: vi.fn(), decrypt: vi.fn(), readProfile: vi.fn(), write: vi.fn(), commit: vi.fn() }));
vi.mock("@/lib/crypto", () => ({ decrypt: mocks.decrypt }));
vi.mock("./postgresDirect", async (original) => ({
  ...await original<typeof import("./postgresDirect")>(), collectDirectFacts: mocks.collect,
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const query = {
    eq: () => query, maybeSingle: () => table === "user_profiles" ? mocks.readProfile() : Promise.resolve({ data: null, error: null }),
    then: (resolve: (value: unknown) => unknown) => Promise.resolve({ error: null }).then(resolve),
  };
  return {
    select: () => query,
    update: (payload: unknown) => { mocks.write(table, payload); return query; },
    insert: (payload: unknown) => { mocks.write(table, payload); return query; },
    upsert: (payload: unknown) => { mocks.write(table, payload); return query; },
  };
} }) }));

import { runDirectPostgresScan } from "./postgresDirectRun";
import { PostgresConnectionError } from "./postgresDirect";
import { CollectorShapeError } from "./apiSchemas";

const encrypted = "encrypted-connection-one";
const epoch = "c".repeat(64);
const dsn = "postgres://private-reader:private-password@private-db.example.com/private-db";
const policies = [{ schemaname: "public", tablename: "invoices", policyname: "read", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] }];
const scanTables = [{ name: "invoices", rlsEnabled: true }];
const facts = { policies, scanTables, grants: [] };
const run = (options: { signal?: AbortSignal } = {}) => runDirectPostgresScan("u", { commit: mocks.commit, ...options });
const sent = () => mocks.commit.mock.calls[0][0];
/** Only the display timestamp may be written outside the fenced commit. */
const evidenceWrites = () => mocks.write.mock.calls.filter(([table]) => table !== "user_profiles");

beforeEach(() => {
  vi.clearAllMocks();
  mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: encrypted, postgres_connection_epoch: epoch }, error: null });
  mocks.decrypt.mockReturnValue(dsn);
  mocks.collect.mockResolvedValue(facts);
  mocks.commit.mockResolvedValue([]);
});

describe("Step 2C-3-C1 / 3F-C2c: direct-Postgres result and provenance", () => {
  it("sends one self-contained snapshot bound to the connection epoch", async () => {
    const created = [{ id: "policy:x", severity: "CRITICAL", title: "t", consequence: "c" }];
    mocks.commit.mockResolvedValue(created);
    expect(await run()).toEqual({ ok: true, findings: 1, newFindings: created });
    expect(sent()).toMatchObject({ transport: "postgres-direct", identity: epoch, retire: true });
    expect(sent().findings).toHaveLength(1);
    expect(sent().facts).toEqual({
      authzProvider: "postgres-rls", policies, scanTables,
      directPostgresSnapshot: {
        collector: "postgres-direct", authzProvider: "postgres-rls", completeness: "unknown",
        connectionFingerprint: epoch, recordedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), policies, scanTables,
      },
    });
    expect(evidenceWrites()).toEqual([]);
    const payload = JSON.stringify(sent());
    for (const privateValue of [encrypted, dsn, "private-reader", "private-password", "private-db.example.com"]) {
      expect(payload).not.toContain(privateValue);
    }
  });

  it("stamps a reconnect with its new epoch and never borrows previous fields", async () => {
    mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: "encrypted-connection-two", postgres_connection_epoch: "e".repeat(64) }, error: null });
    mocks.collect.mockResolvedValue({ policies: [], scanTables: [], grants: [] });
    await run();
    expect(sent().identity).toBe("e".repeat(64));
    expect(sent().facts.directPostgresSnapshot).toMatchObject({ connectionFingerprint: "e".repeat(64), policies: [], scanTables: [] });
    expect(sent().facts.directPostgresSnapshot).not.toHaveProperty("advisors");
    expect(sent().facts.directPostgresSnapshot).not.toHaveProperty("repositoryId");
  });

  it.each([
    { postgres_dsn_encrypted: null, postgres_connection_epoch: epoch },
    { postgres_dsn_encrypted: "", postgres_connection_epoch: epoch },
    { postgres_dsn_encrypted: 42, postgres_connection_epoch: epoch },
    { postgres_dsn_encrypted: encrypted, postgres_connection_epoch: null },
  ])("treats an absent or malformed connection as not connected: %j", async (data) => {
    mocks.readProfile.mockResolvedValue({ data, error: null });
    expect(await run()).toEqual({ ok: false, findings: 0, reason: "not_connected" });
    expect(mocks.collect).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it("refuses a profile read error even if the response also includes connection data", async () => {
    mocks.readProfile.mockResolvedValue({ data: { postgres_dsn_encrypted: encrypted, postgres_connection_epoch: epoch }, error: { message: "private-read-error" } });
    expect(await run()).toMatchObject({ ok: false });
    expect(mocks.collect).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it.each([
    [new PostgresConnectionError("Read-only role required", "not_read_only"), "not_read_only"],
    [new CollectorShapeError("policies", ["invalid"]), "shape_mismatch"],
  ])("commits nothing after a collection failure: %s", async (error, reason) => {
    mocks.collect.mockRejectedValue(error);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: false, reason });
      expect(mocks.commit).not.toHaveBeenCalled();
      expect(mocks.write).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("does not expose a credential or decryption error in logs", async () => {
    mocks.decrypt.mockImplementation(() => { throw new Error(dsn); });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: false, reason: "not_connected" });
      expect(JSON.stringify(log.mock.calls)).not.toContain(dsn);
      expect(mocks.collect).not.toHaveBeenCalled();
      expect(mocks.commit).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("reports a fenced rejection as not committed and writes nothing else", async () => {
    mocks.commit.mockRejectedValue(new Error("Provider result was not committed"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toEqual({ ok: false, findings: 0, reason: "not_committed" });
      expect(mocks.write).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

describe("3F-C2b: an aborted direct-Postgres pass commits nothing", () => {
  it("forwards the signal to collection and stops before the commit", async () => {
    const controller = new AbortController();
    mocks.collect.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return facts;
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run({ signal: controller.signal })).toEqual({ ok: false, findings: 0, reason: "aborted" });
      expect(mocks.collect).toHaveBeenCalledWith(expect.any(Object), undefined, controller.signal);
      expect(mocks.commit).not.toHaveBeenCalled();
      expect(mocks.write).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

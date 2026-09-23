import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import type { ScanResult } from "@/lib/scanner";
import type { CollectorContext } from "./registry";

const mocks = vi.hoisted(() => ({
  scan: vi.fn(), fastScan: vi.fn(), upsert: vi.fn(), snapshot: vi.fn(), alert: vi.fn(),
  graphRead: vi.fn(),
}));
const state = vi.hoisted(() => ({ facts: {} as Record<string, unknown> }));
vi.mock("@/lib/scanner", () => ({ scanProject: mocks.scan, scanCriticalChecks: mocks.fastScan }));
vi.mock("@/lib/crypto", () => ({ decrypt: () => "private-anon-key" }));
vi.mock("./alerts", () => ({ sendNewFindingsAlert: mocks.alert }));
vi.mock("@/lib/security/exposedPathsRun", () => ({ runExposedPathScan: vi.fn() }));
vi.mock("@/lib/graph/narrative", () => ({ generateNarratives: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const read = () => table === "graph_facts" ? mocks.graphRead() :
    Promise.resolve({ data: { findings: [{ id: "old", severity: "WARNING", title: "old", consequence: "old" }] }, error: null });
  const query = {
    eq: () => query, order: () => query, limit: () => query, maybeSingle: read,
    then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) =>
      Promise.resolve({ error: null }).then(resolve, reject),
  };
  return {
    select: () => query, update: () => query, insert: mocks.snapshot,
    upsert: async (row: { facts: Record<string, unknown> }, options: unknown) => {
      const result = await mocks.upsert(row, options);
      if (!result.error) state.facts = row.facts;
      return result;
    },
  };
} }) }));

import { DEFAULT_COLLECTORS, supabaseScanCollector } from "./collectors";
import { runMonitoringPass } from "./run";

const ctx = (): CollectorContext => ({
  profile: { id: "u", email: null, monitored_project_url: "https://project-one.supabase.co", monitored_anon_key_encrypted: "encrypted-key-one" },
  anonKey: "private-anon-key", triggerSource: "scheduled_48h", previousFindings: [],
});
const scanTables = [{ name: "invoices", rlsEnabled: false }, { name: "profiles", rlsEnabled: true }];
const tableReports = scanTables.map((table) => ({ ...table, rlsReadable: true }));
// Deliberately partial fixture: full result parsing belongs to scanner tests.
// Isolate its reported table contract, not untracked per-table RLS reads.
const scan = { tables: tableReports.map((t) => ({ ...t, policies: [], policiesRetrieved: false })) } as unknown as ScanResult;
const fingerprint = (value: string) => createHash("sha256").update(value).digest("hex");

beforeEach(() => {
  vi.clearAllMocks();
  state.facts = { policies: [{ old: "management" }], supabaseManagementSnapshot: { old: "preserve" }, directPostgresSnapshot: { old: "preserve" } };
  mocks.scan.mockResolvedValue(scan);
  mocks.fastScan.mockResolvedValue({ tables: [] });
  mocks.upsert.mockResolvedValue({ error: null });
  mocks.snapshot.mockResolvedValue({ error: null });
  mocks.graphRead.mockImplementation(() => Promise.resolve({ data: { facts: state.facts }, error: null }));
});

describe("Step 2E: endpoint provenance with explicit RLS readability", () => {
  it("returns only scanner table reports with validated target and opaque credential provenance", async () => {
    const context = ctx();
    const result = await supabaseScanCollector.run(context);
    expect(result.facts).toEqual({ collector: "db", merge: true, facts: {
      scanTables,
      supabaseEndpointSnapshot: {
        collector: "supabase-scan", authzProvider: "postgres-rls",
        endpointUrl: "https://project-one.supabase.co", projectRef: "project-one",
        identitySource: "validated-input", connectionFingerprint: fingerprint("encrypted-key-one"),
        recordedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), completeness: "unknown",
        rlsReadability: "complete", tableReports,
      },
    } });
    expect(result.snapshotFindings).toEqual(expect.arrayContaining([expect.objectContaining({ id: "rls:invoices", severity: "CRITICAL" })]));
    expect(mocks.scan).toHaveBeenCalledWith(context.profile.monitored_project_url, context.anonKey, undefined, undefined);
    expect(JSON.stringify(result.facts)).not.toContain("private-anon-key");
    expect(JSON.stringify(result.facts)).not.toContain("encrypted-key-one");
  });

  it("persists through the actual monitoring pass and fact writer, preserving independent producers", async () => {
    expect(DEFAULT_COLLECTORS).toContain(supabaseScanCollector);
    await runMonitoringPass(ctx().profile, "scheduled_48h", [supabaseScanCollector]);
    expect(state.facts.supabaseEndpointSnapshot).toMatchObject({ projectRef: "project-one", tableReports, rlsReadability: "complete" });
    expect(state.facts.supabaseManagementSnapshot).toEqual({ old: "preserve" });
    expect(state.facts.directPostgresSnapshot).toEqual({ old: "preserve" });
    expect(state.facts.policies).toEqual([{ old: "management" }]);
    expect(state.facts._evidence).toMatchObject({ fields: { supabaseEndpointSnapshot: { completeness: "unknown", recordedAt: expect.any(String) } } });
    expect(mocks.upsert.mock.calls[0][0]).toMatchObject({ user_id: "u", collector: "db" });
    expect(mocks.scan).toHaveBeenCalledTimes(1);
  });

  it("replaces the endpoint snapshot after project/key changes even when the scanner reports zero tables", async () => {
    const first = ctx().profile;
    await runMonitoringPass(first, "scheduled_48h", [supabaseScanCollector]);
    mocks.scan.mockResolvedValue({ tables: [] });
    await runMonitoringPass({ ...first, monitored_project_url: "https://project-two.supabase.co", monitored_anon_key_encrypted: "encrypted-key-two" }, "deploy", [supabaseScanCollector]);
    expect(state.facts.supabaseEndpointSnapshot).toMatchObject({
      projectRef: "project-two", connectionFingerprint: fingerprint("encrypted-key-two"), tableReports: [], completeness: "unknown",
    });
    expect(state.facts.supabaseEndpointSnapshot).not.toHaveProperty("policies");
    expect(state.facts.supabaseEndpointSnapshot).not.toHaveProperty("advisors");
    expect(state.facts.supabaseEndpointSnapshot).not.toHaveProperty("repositoryId");
    expect(state.facts.scanTables).toEqual([]);
  });

  it("publishes only observed RLS controls and preserves partial readability", async () => {
    mocks.scan.mockResolvedValue({ tables: [
      { name: "invoices", rlsEnabled: false, rlsReadable: true, policies: [], policiesRetrieved: false },
      { name: "profiles", rlsEnabled: true, rlsReadable: false, policies: [], policiesRetrieved: false },
    ] });

    const result = await supabaseScanCollector.run(ctx());
    expect(result.facts?.facts.scanTables).toEqual([{ name: "invoices", rlsEnabled: false }]);
    expect(result.facts?.facts.supabaseEndpointSnapshot).toMatchObject({
      rlsReadability: "partial",
      tableReports: [
        { name: "invoices", rlsEnabled: false, rlsReadable: true },
        { name: "profiles", rlsEnabled: true, rlsReadable: false },
      ],
    });
  });

  it("does not turn an unread RLS value into a finding or flat control", async () => {
    mocks.scan.mockResolvedValue({ tables: [
      { name: "invoices", rlsEnabled: false, rlsReadable: false, policies: [], policiesRetrieved: false },
    ] });

    const result = await supabaseScanCollector.run(ctx());
    expect(result.snapshotFindings).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "rls:invoices" })])
    );
    expect(result.facts?.facts.scanTables).toEqual([]);
    expect(result.facts?.facts.supabaseEndpointSnapshot).toMatchObject({
      rlsReadability: "unknown",
      tableReports: [{ name: "invoices", rlsEnabled: false, rlsReadable: false }],
    });
  });

  it("does not replace graph provenance on the hourly subset and still carries out-of-scope findings", async () => {
    const context = ctx();
    context.triggerSource = "hourly";
    context.previousFindings = [{ id: "no_rate_limiting", severity: "WARNING", title: "old", consequence: "old" }];
    expect(await supabaseScanCollector.run(context)).toEqual({ snapshotFindings: context.previousFindings });
    expect(mocks.scan).not.toHaveBeenCalled();
    state.facts.supabaseEndpointSnapshot = { old: "preserve" };
    await runMonitoringPass(context.profile, "hourly", [supabaseScanCollector]);
    expect(state.facts.supabaseEndpointSnapshot).toEqual({ old: "preserve" });
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it("captures the supplied target and ciphertext before awaiting a scan", async () => {
    const context = ctx();
    mocks.scan.mockImplementation(async () => {
      context.profile.monitored_project_url = "https://project-two.supabase.co";
      context.profile.monitored_anon_key_encrypted = "encrypted-key-two";
      return scan;
    });
    const result = await supabaseScanCollector.run(context);
    expect(result.facts?.facts.supabaseEndpointSnapshot).toMatchObject({
      endpointUrl: "https://project-one.supabase.co", projectRef: "project-one", connectionFingerprint: fingerprint("encrypted-key-one"),
    });
  });

  it.each([null, "", " ", 42])("does not manufacture credential provenance for invalid ciphertext: %j", async (value) => {
    const context = ctx();
    context.profile.monitored_anon_key_encrypted = value as string;
    const result = await supabaseScanCollector.run(context);
    expect(result.facts?.facts).not.toHaveProperty("supabaseEndpointSnapshot");
    expect(result.facts?.facts.scanTables).toEqual(scanTables);
  });

  it.each([
    "https://project-one.supabase.co?token=private-query", "https://user:private-password@project-one.supabase.co",
    "http://project-one.supabase.co", "https://other.example.com",
  ])("does not manufacture project provenance from an invalid target: %s", async (url) => {
    const context = ctx();
    context.profile.monitored_project_url = url;
    // The scanner is intentionally mocked here: real scanProject rejects this.
    expect((await supabaseScanCollector.run(context)).facts?.facts).not.toHaveProperty("supabaseEndpointSnapshot");
  });

  it("uses the same URL sanitizer as the scanner, not the raw input", async () => {
    const context = ctx();
    context.profile.monitored_project_url = " <b>https://project-one.supabase.co</b> ";
    expect((await supabaseScanCollector.run(context)).facts?.facts.supabaseEndpointSnapshot).toMatchObject({ endpointUrl: "https://project-one.supabase.co", projectRef: "project-one" });
  });

  it("preserves old facts and monitoring findings when the scanner fails", async () => {
    state.facts.supabaseEndpointSnapshot = { old: "preserve" };
    mocks.scan.mockRejectedValue(new Error("unavailable"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runMonitoringPass(ctx().profile, "scheduled_48h", [supabaseScanCollector])).toEqual({ newFindingsCount: 0 });
      expect(state.facts.supabaseEndpointSnapshot).toEqual({ old: "preserve" });
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.snapshot).toHaveBeenCalledWith(expect.objectContaining({
        findings: [expect.objectContaining({ id: "old" })],
        collectors: [expect.objectContaining({ id: "supabase-scan", status: "failed" })],
      }));
      expect(mocks.alert).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it.each(["read", "write"])("preserves old provenance on returned fact-%s errors under the fail-soft writer", async (boundary) => {
    state.facts.supabaseEndpointSnapshot = { old: "preserve" };
    if (boundary === "read") mocks.graphRead.mockResolvedValue({ data: null, error: { message: "unavailable" } });
    else mocks.upsert.mockResolvedValue({ error: { message: "unavailable" } });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runMonitoringPass(ctx().profile, "scheduled_48h", [supabaseScanCollector]);
      expect(state.facts.supabaseEndpointSnapshot).toEqual({ old: "preserve" });
      expect(mocks.snapshot).toHaveBeenCalledTimes(1);
      expect(log).toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

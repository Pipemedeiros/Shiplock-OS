import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadGraphInput, canRetireGraphFindings, runGraphReasoner } from "./graphRun";
import { findAttackPaths } from "./attackPaths";

const reads = vi.hoisted(() => ({ user_profiles: vi.fn(), repositories: vi.fn(), graph_facts: vi.fn(), deep_findings: vi.fn() }));
const filters = vi.hoisted(() => vi.fn());
const writes = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: (table: keyof typeof reads) => {
    const query = {
      eq: (key: string, value: unknown) => { filters(table, key, value); return query; },
      is: () => query,
      maybeSingle: () => reads[table](),
      then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => reads[table]().then(resolve, reject),
    };
    return { select: () => query, insert: writes, update: writes, upsert: writes };
  } }),
}));
vi.mock("./narrative", () => ({ generateNarratives: vi.fn(() => { throw new Error("No model call permitted"); }) }));

const at = "2026-09-17T10:00:00.000Z";
const now = Date.parse("2026-09-17T11:00:00.000Z");
const profile = {
  postgres_dsn_encrypted: "direct-ciphertext",
  supabase_mgmt_token_encrypted: "management-ciphertext", supabase_mgmt_project_ref: "project-a",
  monitored_anon_key_encrypted: "endpoint-ciphertext", monitored_project_url: "https://project-b.supabase.co",
  postgres_connection_epoch: "a".repeat(64), supabase_mgmt_connection_epoch: "b".repeat(64),
  supabase_endpoint_connection_epoch: "c".repeat(64),
};
const policy = { schemaname: "public", tablename: "invoices", policyname: "allow", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] };
const direct = {
  collector: "postgres-direct", authzProvider: "postgres-rls", recordedAt: at, completeness: "unknown",
  connectionFingerprint: profile.postgres_connection_epoch,
  policies: [policy], scanTables: [{ name: "invoices", rlsEnabled: false }],
};
const management = {
  collector: "supabase-management", authzProvider: "postgres-rls", recordedAt: at, completeness: "unknown",
  projectRef: "project-a", connectionFingerprint: profile.supabase_mgmt_connection_epoch,
  policies: [policy], authConfig: { disable_signup: true },
};
const endpoint = {
  collector: "supabase-scan", authzProvider: "postgres-rls", recordedAt: at, completeness: "unknown",
  endpointUrl: profile.monitored_project_url, projectRef: "project-b", identitySource: "validated-input", rlsReadability: "unknown",
  connectionFingerprint: profile.supabase_endpoint_connection_epoch,
  tableReports: [{ name: "invoices", rlsEnabled: true, rlsReadable: false }],
};
const snapshots = { directPostgresSnapshot: direct, supabaseManagementSnapshot: management, supabaseEndpointSnapshot: endpoint };
function facts(value: unknown) {
  reads.graph_facts.mockResolvedValue({ data: [{ collector: "db", facts: value }], error: null });
}
async function input() { return loadGraphInput("owner"); }

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(Date, "now").mockReturnValue(now);
  reads.user_profiles.mockReset().mockResolvedValue({ data: profile, error: null });
  reads.repositories.mockReset().mockResolvedValue({ data: [], error: null });
  reads.graph_facts.mockReset();
  reads.deep_findings.mockReset().mockResolvedValue({ data: [{ finding_id: "old-unbound-path" }], error: null });
  filters.mockReset(); writes.mockReset();
  facts(snapshots);
});

describe("Step 2C-3-C3-A: current-connection database admission through the actual graph loader", () => {
  it("Q6a admits columns only from the current epoch and strips values", async () => {
    const columns = [{ table: "invoices", column: "owner_id", type: "uuid" }];
    facts({ directPostgresSnapshot: { ...direct, columns: columns.map(c => ({ ...c, value: "private" })) } });
    expect((await input()).databaseEvidence?.snapshots.directPostgresSnapshot?.columns).toEqual(columns);
    reads.user_profiles.mockResolvedValue({ data: { ...profile, postgres_connection_epoch: "f".repeat(64) } });
    expect((await input()).databaseEvidence?.snapshots).toEqual({});
  });
  it("keeps all three valid transports separate, without constructing a database/repository join", async () => {
    const result = await input();
    expect(result).toEqual({ databaseEvidence: { admission: "connection-matched", snapshots } });
    expect(result.policies).toBeUndefined(); expect(result.scanTables).toBeUndefined();
    expect(findAttackPaths(result)).toEqual([]); expect(canRetireGraphFindings(result)).toBe(false);
    expect(filters).toHaveBeenCalledWith("graph_facts", "user_id", "owner");
    expect(filters).toHaveBeenCalledWith("user_profiles", "id", "owner");
    expect(writes).not.toHaveBeenCalled();
  });

  it("never admits flat legacy fields or borrows them into an incomplete snapshot", async () => {
    facts({ policies: [policy], scanTables: [{ name: "legacy", rlsEnabled: false }], advisors: [{ name: "legacy" }],
      authConfig: { disable_signup: true }, directPostgresSnapshot: { ...direct, policies: undefined } });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
    expect(reads.user_profiles).not.toHaveBeenCalled();
  });

  it.each([
    ["postgres_dsn_encrypted", null, "directPostgresSnapshot"],
    ["postgres_connection_epoch", "f".repeat(64), "directPostgresSnapshot"],
    ["postgres_dsn_encrypted", 42, "directPostgresSnapshot"],
    ["supabase_mgmt_connection_epoch", "f".repeat(64), "supabaseManagementSnapshot"],
    ["supabase_mgmt_token_encrypted", " ", "supabaseManagementSnapshot"],
    ["supabase_mgmt_project_ref", "other-project", "supabaseManagementSnapshot"],
    ["supabase_mgmt_project_ref", null, "supabaseManagementSnapshot"],
    ["monitored_anon_key_encrypted", null, "supabaseEndpointSnapshot"],
    ["supabase_endpoint_connection_epoch", "f".repeat(64), "supabaseEndpointSnapshot"],
    ["monitored_project_url", "https://different.supabase.co", "supabaseEndpointSnapshot"],
    ["monitored_project_url", "https://example.com", "supabaseEndpointSnapshot"],
    ["monitored_project_url", null, "supabaseEndpointSnapshot"],
  ])("excludes only the changed/disconnected transport: %s", async (key, value, removed) => {
    reads.user_profiles.mockResolvedValue({ data: { ...profile, [key]: value }, error: null });
    const expected = { ...snapshots } as Record<string, unknown>; delete expected[removed];
    expect(await input()).toEqual({ databaseEvidence: { admission: "connection-matched", snapshots: expected } });
  });

  it.each([
    { recordedAt: "2026-09-17T12:00:00Z" }, { recordedAt: "not-a-date" }, { recordedAt: "2026-02-30T10:00:00Z" },
    { recordedAt: "2026-09-17" }, { completeness: "complete" }, { connectionFingerprint: "invalid" },
    { collector: "supabase-management" }, { authzProvider: "firebase-rules" },
    { policies: [{ ...policy, qual: undefined }] }, { policies: [{ ...policy, roles: "{anon}" }] },
    { scanTables: [{ name: "invoices", rlsEnabled: "false" }] }, { policies: null },
  ])("keeps malformed direct evidence unknown rather than empty or protected: %j", async (override) => {
    facts({ directPostgresSnapshot: { ...direct, ...override } });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
  });

  it("preserves successful empty reads without claiming complete coverage", async () => {
    const empty = { ...direct, policies: [], scanTables: [] };
    facts({ directPostgresSnapshot: empty });
    expect(await input()).toEqual({ databaseEvidence: { admission: "connection-matched", snapshots: { directPostgresSnapshot: empty } } });
  });

  it("does not invent a freshness TTL or silently claim an old matching snapshot is fresh", async () => {
    const old = { ...direct, recordedAt: "2025-01-01T00:00:00Z" };
    facts({ directPostgresSnapshot: old });
    expect(await input()).toMatchObject({ databaseEvidence: { snapshots: { directPostgresSnapshot: old } } });
  });

  it("preserves unread versus empty advisors and strips loose auth config/unknown payload keys", async () => {
    facts({ supabaseManagementSnapshot: { ...management, authConfig: { disable_signup: true, smtp_pass: "secret" },
      inventory: [{ secret: "not-this-pass" }], repositoryId: "guessed" }, advisors: [{ name: "stale" }] });
    expect(await input()).toEqual({ databaseEvidence: { admission: "connection-matched", snapshots: { supabaseManagementSnapshot: management } } });
    facts({ supabaseManagementSnapshot: { ...management, advisors: [], authConfig: null } });
    expect(await input()).toMatchObject({ databaseEvidence: { snapshots: { supabaseManagementSnapshot: { advisors: [], authConfig: null } } } });
  });

  it.each([{ advisors: [{ name: 42 }] }, { authConfig: { disable_signup: "true" } }, { authConfig: undefined }, { policies: undefined }, { projectRef: " " }])(
    "rejects a malformed management payload without borrowing fields: %j", async (override) => {
      facts({ supabaseManagementSnapshot: { ...management, ...override } });
      expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
    });

  it.each([{ projectRef: "project-a" }, { endpointUrl: "https://project-b.supabase.co/" },
    { rlsReadability: "read" }, { rlsReadability: "complete" }, { identitySource: "provider" },
    { tableReports: [{ name: "invoices", rlsEnabled: null, rlsReadable: true }] }])(
    "rejects an inconsistent or invented endpoint contract: %j", async (override) => {
      facts({ supabaseEndpointSnapshot: { ...endpoint, ...override } });
      expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
    });

  it("normalizes the current endpoint using the producer's validator but keeps reports out of controls", async () => {
    reads.user_profiles.mockResolvedValue({ data: { ...profile, monitored_project_url: " <b>https://project-b.supabase.co</b> " }, error: null });
    facts({ supabaseEndpointSnapshot: endpoint, policies: [policy] });
    const result = await input();
    expect(result).toEqual({ databaseEvidence: { admission: "connection-matched", snapshots: { supabaseEndpointSnapshot: endpoint } } });
    expect(result.scanTables).toBeUndefined(); expect(result.policies).toBeUndefined();
  });

  it.each([null, [], "malformed", { unknown: true }])("refuses malformed/missing profile state: %j", async (data) => {
    reads.user_profiles.mockResolvedValue({ data, error: null });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
  });

  it("excludes all DB context on a returned profile error and does not expose the error or credential", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    reads.user_profiles.mockResolvedValue({ data: profile, error: { message: "private-connection-detail" } });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
    expect(JSON.stringify(log.mock.calls)).not.toContain("private-connection-detail");
    expect(JSON.stringify(log.mock.calls)).not.toContain(profile.postgres_dsn_encrypted);
  });

  it("excludes all DB context on a thrown profile read", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    reads.user_profiles.mockRejectedValue(new Error("private-connection-detail"));
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
  });

  it("refuses ambiguous duplicate DB rows rather than choosing a convenient snapshot", async () => {
    reads.graph_facts.mockResolvedValue({ data: [{ collector: "db", facts: snapshots }, { collector: "db", facts: {} }] });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
  });

  it("retains previous findings when every DB snapshot is excluded; no model call, insert or archive", async () => {
    reads.user_profiles.mockResolvedValue({ data: null, error: null });
    expect(await runGraphReasoner("owner")).toEqual({ total: 0, newCount: 0, resolvedCount: 0, retainedCount: 1 });
    expect(writes).not.toHaveBeenCalled();
  });

  it("does not read connection credentials when no DB collector exists", async () => {
    reads.graph_facts.mockResolvedValue({ data: [{ collector: "runtime", facts: { providersRead: [] } }] });
    expect(await input()).toEqual({ runtimeProvidersRead: [] });
    expect(reads.user_profiles).not.toHaveBeenCalled();
  });

  it.each([null, [], "malformed"])("keeps malformed database payloads unknown: %j", async (payload) => {
    facts(payload);
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
    expect(reads.user_profiles).not.toHaveBeenCalled();
  });

  it("does not reinterpret another transport's payload even with a matching connection", async () => {
    facts({ directPostgresSnapshot: management, supabaseManagementSnapshot: direct });
    expect(await input()).toEqual({ databaseEvidence: { admission: "unknown", snapshots: {} } });
  });

  it("propagates a findings-read error without attempting retirement after unknown admission", async () => {
    reads.user_profiles.mockResolvedValue({ data: null, error: null });
    reads.deep_findings.mockResolvedValue({ data: null, error: { message: "findings read failed" } });
    await expect(runGraphReasoner("owner")).rejects.toThrow("Graph findings could not be read");
    expect(writes).not.toHaveBeenCalled();
  });
});

describe("2D-2: database admission matches connection epochs", () => {
  const epochs = { postgres_connection_epoch: "1".repeat(64), supabase_mgmt_connection_epoch: "2".repeat(64), supabase_endpoint_connection_epoch: "3".repeat(64) };
  const stamped = {
    directPostgresSnapshot: { ...direct, connectionFingerprint: epochs.postgres_connection_epoch },
    supabaseManagementSnapshot: { ...management, connectionFingerprint: epochs.supabase_mgmt_connection_epoch },
    supabaseEndpointSnapshot: { ...endpoint, connectionFingerprint: epochs.supabase_endpoint_connection_epoch },
  };

  it("admits snapshots after a refresh re-encrypted every credential", async () => {
    reads.user_profiles.mockResolvedValue({ data: {
      ...profile, ...epochs, postgres_dsn_encrypted: "re-encrypted-direct",
      supabase_mgmt_token_encrypted: "refreshed-management", monitored_anon_key_encrypted: "re-encrypted-endpoint",
    }, error: null });
    facts(stamped);
    const { loadCurrentDatabaseEvidence } = await import("./databaseSource");
    const evidence = await loadCurrentDatabaseEvidence("owner", stamped, now);
    expect(Object.keys(evidence.snapshots).sort()).toEqual(["directPostgresSnapshot", "supabaseEndpointSnapshot", "supabaseManagementSnapshot"]);
  });

  it("rejects every snapshot after a true reconnect minted new epochs", async () => {
    reads.user_profiles.mockResolvedValue({ data: {
      ...profile, postgres_connection_epoch: "4".repeat(64), supabase_mgmt_connection_epoch: "5".repeat(64), supabase_endpoint_connection_epoch: "6".repeat(64),
    }, error: null });
    const { loadCurrentDatabaseEvidence } = await import("./databaseSource");
    const evidence = await loadCurrentDatabaseEvidence("owner", stamped, now);
    expect(evidence).toEqual({ admission: "unknown", snapshots: {} });
  });
});

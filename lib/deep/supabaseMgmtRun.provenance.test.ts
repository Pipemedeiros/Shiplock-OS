import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  profile: vi.fn(), refreshWrite: vi.fn(), encrypt: vi.fn(), usable: vi.fn(),
  policies: vi.fn(), advisors: vi.fn(), auth: vi.fn(), columns: vi.fn(),
  upsert: vi.fn(), insert: vi.fn(), archive: vi.fn(), proving: vi.fn(), commit: vi.fn(),
}));
const state = vi.hoisted(() => ({ facts: {} as Record<string, unknown>, refreshFilters: [] as unknown[][] }));
vi.mock("@/lib/crypto", () => ({ encrypt: mocks.encrypt }));
vi.mock("./supabaseMgmt", async (original) => ({
  ...await original<typeof import("./supabaseMgmt")>(),
  getUsableToken: mocks.usable, fetchPolicies: mocks.policies,
  fetchAdvisors: mocks.advisors, fetchAuthConfig: mocks.auth,
  fetchSchemaColumns: mocks.columns, fetchRowCounts: vi.fn().mockResolvedValue(new Map()),
  fetchColumnGrants: vi.fn().mockResolvedValue([]),
  fetchDatabaseCapabilities: vi.fn().mockResolvedValue({ extensions: [] }),
  fetchStorageConfig: vi.fn().mockResolvedValue({}), fetchBackupConfig: vi.fn().mockResolvedValue(null),
  fetchRealtimeAndHooks: vi.fn().mockResolvedValue({}), fetchAuthAuditLog: vi.fn().mockResolvedValue([]),
}));
vi.mock("@/lib/graph/narrative", () => ({ generateNarratives: vi.fn() }));
vi.mock("@/lib/runtime/authRun", () => ({ runAuthLogScan: vi.fn() }));
vi.mock("@/lib/proving/run", () => ({ runProvingGround: mocks.proving }));
vi.mock("@/lib/proving/host", () => ({ provingHost: vi.fn() }));
const edge = vi.hoisted(() => vi.fn());
vi.mock("@/lib/traffic/edgeCollect", () => ({ collectSupabaseEdgeTraffic: edge }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  let updating = false;
  let settings = false;
  const read = () => updating ? mocks.refreshWrite() : table === "user_profiles"
    ? settings ? Promise.resolve({ data: { proving_ground_enabled: false }, error: null }) : mocks.profile()
    : Promise.resolve({ data: table === "graph_facts" ? { facts: state.facts } : [], error: null });
  const query = {
    eq: (...args: unknown[]) => { if (updating) state.refreshFilters.push(args); return query; },
    is: () => query, maybeSingle: read, in: mocks.archive,
    select: () => query,
    then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) => read().then(resolve, reject),
  };
  return {
    select: (fields: string) => { settings = fields.includes("proving_ground_enabled"); return query; },
    update: () => { updating = true; return query; }, insert: mocks.insert,
    upsert: async (row: { facts: Record<string, unknown> }, options: unknown) => {
      const result = await mocks.upsert(row, options);
      if (!result.error) state.facts = row.facts;
      return result;
    },
  };
} }) }));

import { runPolicyScan } from "./supabaseMgmtRun";
import type { ProviderResult } from "@/lib/monitoring/registry";

// The runner hands one result to the monitor worker's fenced commit (3F-C2c).
// This double applies facts the way the SQL merge does (proven in the SQL
// suite) so provenance assertions read the resulting state.
const run = (options: { signal?: AbortSignal } = {}) => runPolicyScan("u", { commit: mocks.commit, ...options });
const sent = () => mocks.commit.mock.calls[0][0] as ProviderResult;
import { CollectorShapeError } from "./apiSchemas";

const encrypted = "encrypted-access-one";
const project = "project-one";
const policies = [{ schemaname: "public", tablename: "invoices", policyname: "read", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] }];
const profile = {
  supabase_mgmt_token_encrypted: encrypted, supabase_mgmt_refresh_encrypted: "encrypted-refresh",
  supabase_mgmt_project_ref: project, supabase_mgmt_expires_at: null,
  monitored_app_url: "https://app.example.com",
  supabase_mgmt_connection_epoch: "a".repeat(64),
};

beforeEach(() => {
  vi.clearAllMocks();
  state.refreshFilters = [];
  state.facts = { advisors: [{ name: "old-advisor" }], directPostgresSnapshot: { old: "preserve" } };
  mocks.profile.mockResolvedValue({ data: profile, error: null });
  mocks.usable.mockResolvedValue({ token: { accessToken: "private-access", refreshToken: "private-refresh", expiresAt: null }, refreshed: false });
  mocks.encrypt.mockImplementation((value: string) => value === "private-access" ? "encrypted-access-two" : "encrypted-refresh-two");
  mocks.refreshWrite.mockResolvedValue({ data: { supabase_mgmt_token_encrypted: "encrypted-access-two" }, error: null });
  mocks.policies.mockResolvedValue(policies);
  mocks.advisors.mockResolvedValue([]);
  mocks.auth.mockResolvedValue({ disable_signup: false, mailer_autoconfirm: true, site_url: "https://app.example.com", smtp_pass: "private-smtp", external_google_secret: "private-oauth" });
  mocks.columns.mockResolvedValue([]);
  mocks.upsert.mockResolvedValue({ error: null });
  mocks.insert.mockResolvedValue({ error: null });
  mocks.archive.mockResolvedValue({ error: null });
  mocks.commit.mockImplementation(async (result: ProviderResult) => {
    if (result.facts) state.facts = { ...state.facts, ...result.facts };
    return result.findings;
  });
});

describe("Step 2C-3-C2-A: Supabase Management project and credential provenance", () => {
  it("persists only this pass's facts with project, opaque fingerprint and unknown completeness", async () => {
    state.facts.authConfig = { smtp_pass: "previous-private-smtp", mailer_autoconfirm: false };
    const result = await run();
    expect(result).toMatchObject({ ok: true, newFindings: expect.any(Array) });
    expect(result.newFindings!.length).toBeGreaterThan(0);
    expect(state.facts.supabaseManagementSnapshot).toEqual({
      collector: "supabase-management", authzProvider: "postgres-rls", projectRef: project,
      connectionFingerprint: "a".repeat(64), recordedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      completeness: "unknown", policies, advisors: [],
      authConfig: { disable_signup: false, mailer_autoconfirm: true },
    });
    expect(state.facts.directPostgresSnapshot).toEqual({ old: "preserve" });
    expect(sent()).toMatchObject({ transport: "supabase-management", identity: "a".repeat(64), retire: true });
    expect(mocks.policies).toHaveBeenCalledWith("private-access", project, undefined);
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.insert).not.toHaveBeenCalled();
    expect(mocks.proving).not.toHaveBeenCalled();
    expect(state.facts.authConfig).toEqual({ disable_signup: false, mailer_autoconfirm: true });
    const stored = JSON.stringify(state.facts);
    for (const secret of [encrypted, "encrypted-refresh", "private-access", "private-refresh", "private-smtp", "previous-private-smtp", "private-oauth", "smtp_pass", "external_google_secret"]) {
      expect(stored).not.toContain(secret);
    }
  });

  it("replaces snapshots on project/credential change rather than borrowing merged facts", async () => {
    await run();
    mocks.profile.mockResolvedValue({ data: { ...profile, supabase_mgmt_project_ref: "project-two", supabase_mgmt_token_encrypted: "encrypted-access-three", supabase_mgmt_connection_epoch: "b".repeat(64) }, error: null });
    mocks.policies.mockResolvedValue([]);
    mocks.advisors.mockRejectedValue(new Error("unavailable"));
    mocks.auth.mockResolvedValue(null);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: true });
      expect(state.facts.supabaseManagementSnapshot).toMatchObject({
        projectRef: "project-two", connectionFingerprint: "b".repeat(64), policies: [], authConfig: null,
      });
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("advisors");
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("scanTables");
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("repositoryId");
    } finally { log.mockRestore(); }
  });

  it("retains failed advisor observations only in legacy fields, never in the new snapshot", async () => {
    mocks.advisors.mockRejectedValue(new Error("unavailable"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: true });
      expect(state.facts.advisors).toEqual([{ name: "old-advisor" }]);
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("advisors");
    } finally { log.mockRestore(); }
  });

  it("keeps failed auth reads unknown and never coerces strings to verified boolean flags", async () => {
    mocks.auth.mockResolvedValue(null);
    await run();
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("authConfig", null);
    mocks.auth.mockResolvedValue({ disable_signup: "false", mailer_autoconfirm: "true", smtp_pass: "private-smtp" });
    await run();
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("authConfig", {});
  });

  it("still runs existing redirect and password checks against the full in-memory config", async () => {
    mocks.auth.mockResolvedValue({
      disable_signup: false, mailer_autoconfirm: true, site_url: "https://app.example.com",
      uri_allow_list: "**", password_min_length: 4, smtp_pass: "private-smtp",
    });
    const result = await run();
    expect(result).toMatchObject({ ok: true, newFindings: expect.any(Array) });
    expect(result.newFindings?.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      "auth_redirect:wildcard_any_host", "auth_policy:weak_password_length",
    ]));
    expect(sent().findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      "auth_redirect:wildcard_any_host", "auth_policy:weak_password_length",
    ]));
    expect(state.facts.authConfig).toEqual({ disable_signup: false, mailer_autoconfirm: true });
    expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("authConfig.smtp_pass");
  });

  it("does not borrow old inventory after the optional schema read fails", async () => {
    state.facts.inventory = [{ table: "old-project-table" }];
    mocks.columns.mockRejectedValue(new Error("unavailable"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: true });
      expect(state.facts.inventory).toEqual([{ table: "old-project-table" }]);
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("inventory");
      expect(sent().facts).not.toHaveProperty("inventory");
    } finally { log.mockRestore(); }
  });

  it.each([
    { supabase_mgmt_token_encrypted: null }, { supabase_mgmt_token_encrypted: 42 },
    { supabase_mgmt_project_ref: "" }, { supabase_mgmt_project_ref: 42 },
  ])("refuses malformed/disconnected profile inputs: %j", async (override) => {
    mocks.profile.mockResolvedValue({ data: { ...profile, ...override }, error: null });
    expect(await run()).toMatchObject({ ok: false });
    expect(mocks.usable).not.toHaveBeenCalled();
    expect(mocks.policies).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it("does not collect when profile data accompanies a returned read error", async () => {
    mocks.profile.mockResolvedValue({ data: profile, error: { message: "read failed" } });
    expect(await run()).toMatchObject({ ok: false });
    expect(mocks.usable).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it("keeps the connection epoch across a refresh (2D) and guards the old project/credential", async () => {
    mocks.usable.mockResolvedValue({ token: { accessToken: "private-access", refreshToken: "private-refresh", expiresAt: null }, refreshed: true });
    expect(await run()).toMatchObject({ ok: true });
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("connectionFingerprint", "a".repeat(64));
    expect(state.refreshFilters).toEqual([["id", "u"], ["supabase_mgmt_project_ref", project], ["supabase_mgmt_token_encrypted", encrypted]]);
  });

  it.each([
    { data: null, error: { message: "refresh write failed" } },
    { data: null, error: null },
    { data: { supabase_mgmt_token_encrypted: "different-credential" }, error: null },
  ])("does not collect when refresh persistence is unconfirmed: %j", async (result) => {
    mocks.usable.mockResolvedValue({ token: { accessToken: "private-access", refreshToken: null, expiresAt: null }, refreshed: true });
    mocks.refreshWrite.mockResolvedValue(result);
    expect(await run()).toMatchObject({ ok: false, reason: "auth_failed" });
    expect(mocks.policies).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });

  it("preserves old snapshots and findings on load-bearing policy shape failure", async () => {
    state.facts.supabaseManagementSnapshot = { old: "preserve" };
    mocks.policies.mockRejectedValue(new CollectorShapeError("policies", ["invalid"]));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: false, reason: "shape_mismatch" });
      expect(state.facts.supabaseManagementSnapshot).toEqual({ old: "preserve" });
      expect(mocks.commit).not.toHaveBeenCalled();
      expect(mocks.insert).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("does not collect or disclose credentials after token/decryption failure", async () => {
    mocks.usable.mockRejectedValue(new Error("private-access"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await run()).toMatchObject({ ok: false, reason: "auth_failed" });
      expect(mocks.policies).not.toHaveBeenCalled();
      expect(mocks.commit).not.toHaveBeenCalled();
      expect(JSON.stringify(log.mock.calls)).not.toContain("private-access");
    } finally { log.mockRestore(); }
  });
});

describe("3F-C2b: an aborted Supabase Management pass writes no evidence", () => {
  it("forwards the signal to reads and stops before facts, findings, or proving", async () => {
    const controller = new AbortController();
    mocks.policies.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return policies;
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await run({ signal: controller.signal });
      expect(result).toEqual({ ok: false, findings: 0, reason: "aborted" });
      expect(mocks.policies).toHaveBeenCalledWith("private-access", project, controller.signal);
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.commit).not.toHaveBeenCalled();
      expect(mocks.insert).not.toHaveBeenCalled();
      expect(mocks.archive).not.toHaveBeenCalled();
      expect(mocks.proving).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("still stores a rotated OAuth token so an abort cannot strand the connection", async () => {
    const controller = new AbortController();
    mocks.usable.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return { token: { accessToken: "private-access", refreshToken: "private-refresh", expiresAt: null }, refreshed: true };
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await run({ signal: controller.signal });
      expect(mocks.usable).toHaveBeenCalledWith(profile);
      expect(mocks.refreshWrite).toHaveBeenCalledTimes(1);
      expect(result).toEqual({ ok: false, findings: 0, reason: "aborted" });
      expect(mocks.policies).not.toHaveBeenCalled();
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.commit).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

describe("2D-2: Supabase Management identity is the connection epoch", () => {
  it("treats a credential without a valid epoch as not connected", async () => {
    mocks.profile.mockResolvedValue({ data: { ...profile, supabase_mgmt_connection_epoch: null }, error: null });
    expect(await run()).toEqual({ ok: false, findings: 0, reason: "not_connected" });
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.commit).not.toHaveBeenCalled();
  });
});

describe("3F-C2c: fenced commit from the monitor worker", () => {
  it("sends snapshot, inventory, and findings in one result without writing any itself", async () => {
    mocks.columns.mockResolvedValue([{ table: "invoices", column: "id" }]);
    await run();
    expect(sent().facts).toMatchObject({
      policies, supabaseManagementSnapshot: expect.objectContaining({ connectionFingerprint: "a".repeat(64) }),
      inventory: expect.anything(),
    });
    expect(sent().facts).not.toHaveProperty("_evidence");
    expect(sent().findings.length).toBeGreaterThan(0);
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.insert).not.toHaveBeenCalled();
    expect(mocks.archive).not.toHaveBeenCalled();
  });

  it("stops before side effects when the fence rejects the commit", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      mocks.commit.mockRejectedValue(new Error("Provider result was not committed"));
      expect(await run()).toEqual({ ok: false, findings: 0, reason: "not_committed" });
      expect(mocks.proving).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

describe("Step 5A-1: a failed Supabase read never retires that family's findings", () => {
  const complete = async () => {
    const api = await import("./supabaseMgmt");
    vi.mocked(api.fetchColumnGrants).mockResolvedValueOnce([]);
    vi.mocked(api.fetchDatabaseCapabilities).mockResolvedValueOnce({ extensions: [], networkGrants: [], cronJobs: [], foreignServers: [] });
    vi.mocked(api.fetchStorageConfig).mockResolvedValueOnce({ buckets: [], policies: [] });
    vi.mocked(api.fetchBackupConfig).mockResolvedValueOnce({ pitrEnabled: true, walgEnabled: true });
    vi.mocked(api.fetchRealtimeAndHooks).mockResolvedValueOnce({ realtimeTables: [], authHooks: [] });
    return api;
  };

  it("marks nothing unread when every read succeeded", async () => {
    await complete();
    await run();
    expect(sent().unread).toEqual([]);
    expect(sent().snapshot).toEqual({ scope: project, failed: [] });
  });

  it("marks each failed read's finding family unread", async () => {
    const api = await import("./supabaseMgmt");
    vi.mocked(api.fetchColumnGrants).mockResolvedValueOnce(null);
    vi.mocked(api.fetchDatabaseCapabilities).mockResolvedValueOnce({ extensions: [], networkGrants: undefined, cronJobs: undefined, foreignServers: [] });
    vi.mocked(api.fetchStorageConfig).mockResolvedValueOnce({ buckets: undefined, policies: [] });
    vi.mocked(api.fetchBackupConfig).mockResolvedValueOnce(null);
    vi.mocked(api.fetchRealtimeAndHooks).mockResolvedValueOnce({ realtimeTables: [], authHooks: undefined });
    mocks.advisors.mockRejectedValue(new Error("shape changed"));
    mocks.auth.mockResolvedValue(null);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try { await run(); } finally { log.mockRestore(); }
    expect(sent().retire).toBe(true);
    expect([...sent().unread!].sort()).toEqual([
      "advisor:", "auth_hook:", "auth_policy:", "auth_redirect:", "auth_site_url:",
      "extensions:cron_", "extensions:network_callable_by_public_role",
      "grants:", "storage:no_pitr", "storage:unrestricted_uploads:",
    ]);
    expect(sent().snapshot.failed).toEqual(sent().unread);
  });
});

describe("Q8 / 2F-5b: the gateway traffic read leaves a snapshot", () => {
  it.each([
    [{ status: "read", repositories: 1, judgedSources: 0 }, [[project, true]]],
    [{ status: "unread" }, [[project, false]]],
    [{ status: "unbound" }, []],
    [{ status: "not_enabled" }, []],
  ])("records %o as %o", async (outcome, calls) => {
    edge.mockResolvedValue(outcome);
    const recordEdgeTraffic = vi.fn(async () => {});
    await runPolicyScan("u", { commit: mocks.commit, recordEdgeTraffic });
    expect(recordEdgeTraffic.mock.calls).toEqual(calls);
  });
  it("records a collection that threw as unread, and survives a recorder failure", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    edge.mockRejectedValue(new Error("observations could not be stored"));
    const recordEdgeTraffic = vi.fn(async () => { throw new Error("lease gone"); });
    const result = await runPolicyScan("u", { commit: mocks.commit, recordEdgeTraffic });
    log.mockRestore();
    expect(recordEdgeTraffic).toHaveBeenCalledWith(project, false);
    expect(result.ok).toBe(true);
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

const mocks = vi.hoisted(() => ({
  profile: vi.fn(), refreshWrite: vi.fn(), encrypt: vi.fn(), usable: vi.fn(),
  policies: vi.fn(), advisors: vi.fn(), auth: vi.fn(), columns: vi.fn(),
  upsert: vi.fn(), insert: vi.fn(), archive: vi.fn(), proving: vi.fn(),
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
import { CollectorShapeError } from "./apiSchemas";

const encrypted = "encrypted-access-one";
const project = "project-one";
const policies = [{ schemaname: "public", tablename: "invoices", policyname: "read", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] }];
const profile = {
  supabase_mgmt_token_encrypted: encrypted, supabase_mgmt_refresh_encrypted: "encrypted-refresh",
  supabase_mgmt_project_ref: project, supabase_mgmt_expires_at: null,
  monitored_app_url: "https://app.example.com",
};
const fingerprint = (value: string) => createHash("sha256").update(value).digest("hex");

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
});

describe("Step 2C-3-C2-A: Supabase Management project and credential provenance", () => {
  it("persists only this pass's facts with project, opaque fingerprint and unknown completeness", async () => {
    state.facts.authConfig = { smtp_pass: "previous-private-smtp", mailer_autoconfirm: false };
    expect(await runPolicyScan("u")).toMatchObject({ ok: true });
    expect(state.facts.supabaseManagementSnapshot).toEqual({
      collector: "supabase-management", authzProvider: "postgres-rls", projectRef: project,
      connectionFingerprint: fingerprint(encrypted), recordedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      completeness: "unknown", policies, advisors: [],
      authConfig: { disable_signup: false, mailer_autoconfirm: true },
    });
    expect(state.facts.directPostgresSnapshot).toEqual({ old: "preserve" });
    expect(state.facts._evidence).toMatchObject({ fields: { supabaseManagementSnapshot: { completeness: "unknown" } } });
    expect(mocks.policies).toHaveBeenCalledWith("private-access", project);
    expect(mocks.upsert.mock.calls[0][0].user_id).toBe("u");
    expect(mocks.proving).not.toHaveBeenCalled();
    expect(state.facts.authConfig).toEqual({ disable_signup: false, mailer_autoconfirm: true });
    const stored = JSON.stringify(state.facts);
    for (const secret of [encrypted, "encrypted-refresh", "private-access", "private-refresh", "private-smtp", "previous-private-smtp", "private-oauth", "smtp_pass", "external_google_secret"]) {
      expect(stored).not.toContain(secret);
    }
  });

  it("replaces snapshots on project/credential change rather than borrowing merged facts", async () => {
    await runPolicyScan("u");
    mocks.profile.mockResolvedValue({ data: { ...profile, supabase_mgmt_project_ref: "project-two", supabase_mgmt_token_encrypted: "encrypted-access-three" }, error: null });
    mocks.policies.mockResolvedValue([]);
    mocks.advisors.mockRejectedValue(new Error("unavailable"));
    mocks.auth.mockResolvedValue(null);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runPolicyScan("u")).toMatchObject({ ok: true });
      expect(state.facts.supabaseManagementSnapshot).toMatchObject({
        projectRef: "project-two", connectionFingerprint: fingerprint("encrypted-access-three"), policies: [], authConfig: null,
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
      expect(await runPolicyScan("u")).toMatchObject({ ok: true });
      expect(state.facts.advisors).toEqual([{ name: "old-advisor" }]);
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("advisors");
    } finally { log.mockRestore(); }
  });

  it("keeps failed auth reads unknown and never coerces strings to verified boolean flags", async () => {
    mocks.auth.mockResolvedValue(null);
    await runPolicyScan("u");
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("authConfig", null);
    mocks.auth.mockResolvedValue({ disable_signup: "false", mailer_autoconfirm: "true", smtp_pass: "private-smtp" });
    await runPolicyScan("u");
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("authConfig", {});
  });

  it("still runs existing redirect and password checks against the full in-memory config", async () => {
    mocks.auth.mockResolvedValue({
      disable_signup: false, mailer_autoconfirm: true, site_url: "https://app.example.com",
      uri_allow_list: "**", password_min_length: 4, smtp_pass: "private-smtp",
    });
    expect(await runPolicyScan("u")).toMatchObject({ ok: true });
    const inserted = mocks.insert.mock.calls[0][0] as { finding_id: string }[];
    expect(inserted.map((row) => row.finding_id)).toEqual(expect.arrayContaining([
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
      expect(await runPolicyScan("u")).toMatchObject({ ok: true });
      expect(state.facts.inventory).toEqual([{ table: "old-project-table" }]);
      expect(state.facts.supabaseManagementSnapshot).not.toHaveProperty("inventory");
      expect(mocks.upsert).toHaveBeenCalledTimes(1);
    } finally { log.mockRestore(); }
  });

  it.each([
    { supabase_mgmt_token_encrypted: null }, { supabase_mgmt_token_encrypted: 42 },
    { supabase_mgmt_project_ref: "" }, { supabase_mgmt_project_ref: 42 },
  ])("refuses malformed/disconnected profile inputs: %j", async (override) => {
    mocks.profile.mockResolvedValue({ data: { ...profile, ...override }, error: null });
    expect(await runPolicyScan("u")).toMatchObject({ ok: false });
    expect(mocks.usable).not.toHaveBeenCalled();
    expect(mocks.policies).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it("does not collect when profile data accompanies a returned read error", async () => {
    mocks.profile.mockResolvedValue({ data: profile, error: { message: "read failed" } });
    expect(await runPolicyScan("u")).toMatchObject({ ok: false });
    expect(mocks.usable).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
  });

  it("uses the newly persisted ciphertext fingerprint after refresh and guards the old project/credential", async () => {
    mocks.usable.mockResolvedValue({ token: { accessToken: "private-access", refreshToken: "private-refresh", expiresAt: null }, refreshed: true });
    expect(await runPolicyScan("u")).toMatchObject({ ok: true });
    expect(state.facts.supabaseManagementSnapshot).toHaveProperty("connectionFingerprint", fingerprint("encrypted-access-two"));
    expect(state.refreshFilters).toEqual([["id", "u"], ["supabase_mgmt_project_ref", project], ["supabase_mgmt_token_encrypted", encrypted]]);
  });

  it.each([
    { data: null, error: { message: "refresh write failed" } },
    { data: null, error: null },
    { data: { supabase_mgmt_token_encrypted: "different-credential" }, error: null },
  ])("does not collect when refresh persistence is unconfirmed: %j", async (result) => {
    mocks.usable.mockResolvedValue({ token: { accessToken: "private-access", refreshToken: null, expiresAt: null }, refreshed: true });
    mocks.refreshWrite.mockResolvedValue(result);
    expect(await runPolicyScan("u")).toMatchObject({ ok: false, reason: "auth_failed" });
    expect(mocks.policies).not.toHaveBeenCalled();
    expect(mocks.upsert).not.toHaveBeenCalled();
    expect(mocks.archive).not.toHaveBeenCalled();
  });

  it("preserves old snapshots and findings on load-bearing policy shape failure", async () => {
    state.facts.supabaseManagementSnapshot = { old: "preserve" };
    mocks.policies.mockRejectedValue(new CollectorShapeError("policies", ["invalid"]));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runPolicyScan("u")).toMatchObject({ ok: false, reason: "shape_mismatch" });
      expect(state.facts.supabaseManagementSnapshot).toEqual({ old: "preserve" });
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.archive).not.toHaveBeenCalled();
      expect(mocks.insert).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it("does not collect or disclose credentials after token/decryption failure", async () => {
    mocks.usable.mockRejectedValue(new Error("private-access"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runPolicyScan("u")).toMatchObject({ ok: false, reason: "auth_failed" });
      expect(mocks.policies).not.toHaveBeenCalled();
      expect(mocks.upsert).not.toHaveBeenCalled();
      expect(mocks.archive).not.toHaveBeenCalled();
      expect(JSON.stringify(log.mock.calls)).not.toContain("private-access");
    } finally { log.mockRestore(); }
  });

  it("preserves the old snapshot after returned fact-write failure under the existing fail-soft contract", async () => {
    state.facts.supabaseManagementSnapshot = { old: "preserve" };
    mocks.upsert.mockResolvedValue({ error: { message: "write unavailable" } });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(await runPolicyScan("u")).toMatchObject({ ok: true });
      expect(state.facts.supabaseManagementSnapshot).toEqual({ old: "preserve" });
      expect(log).toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
});

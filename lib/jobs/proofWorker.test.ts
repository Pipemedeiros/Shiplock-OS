import { beforeEach, expect, it, vi } from "vitest";
const m = vi.hoisted(() => ({ read: vi.fn(), rpc: vi.fn(), filters: vi.fn(), db: vi.fn(), host: vi.fn(), run: vi.fn(), close: vi.fn(), hosted: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: m.rpc, from: (table: string) => {
  const q = { select: () => q, eq: (k: string, v: unknown) => { m.filters(table, k, v); return q; }, is: (k: string, v: unknown) => { m.filters(table,k,v); return q; }, maybeSingle: () => m.read(table) };
  return q;
} }) }));
vi.mock("@/lib/graph/repositoryDatabase", () => ({ loadRepositoryDatabaseEvidence: m.db }));
vi.mock("@/lib/proving/embeddedHost", () => ({ openEmbeddedHost: m.host }));
vi.mock("@/lib/proving/host", () => ({ provingHost: m.hosted }));
import { executeProofJob } from "./proofWorker";
import type { ClaimedJob } from "./queue";
const id = "11111111-1111-4111-8111-111111111111";
const user = "22222222-2222-4222-8222-222222222222";
const repo = "33333333-3333-4333-8333-333333333333";
const authorization = "44444444-4444-4444-8444-444444444444";
const job = { id, user_id: user, repository_id: repo, kind: "proof", audit_run_id: null, deduplication_key: `proof:${authorization}`, lease_token: id, lease_until: "2099-01-01T00:00:00Z", checkpoint: 0 } as ClaimedJob;
let rows: Record<string, unknown>, budget: number, control: number, leak: number;
const policy = { schemaname: "public", tablename: "orders", policyname: "p", roles: ["authenticated"], cmd: "SELECT", qual: "true", with_check: null };
beforeEach(() => {
  vi.clearAllMocks(); budget = 60; control = 1; leak = 0;
  rows = { proof_runs: null, repositories: { selected: true }, user_profiles: { proving_ground_enabled: true, autonomy_kill_switch: false },
    deep_findings: { finding_id: "f", blast_radius: "orders", archived_at: null } };
  m.read.mockImplementation(async table => ({ data: table === "proof_authorizations" ? { id: authorization, user_id: user, repository_id: repo, finding_id: "f", table_name: "public.orders", target_kind: "replica", status: "consumed", statement_budget: budget, expires_at: "2099-01-01T00:00:00Z" } : rows[table], error: null }));
  m.rpc.mockResolvedValue({ data: null, error: null });
  m.db.mockResolvedValue({ admission: "connection-matched", snapshots: { directPostgresSnapshot: { policies: [policy], columns: [{ table: "orders", column: "owner_id", type: "uuid" }] } } });
  m.run.mockImplementation(async (_ref, sql: string) => /as visible/.test(sql) ? [{ visible: control }] : /as leaked/.test(sql) ? [{ leaked: leak, own: 1 }] : []);
  m.close.mockResolvedValue(undefined);
  m.host.mockResolvedValue({ token: "", projectRef: "embedded-test", run: m.run, close: m.close });
});
const recorded = () => m.rpc.mock.calls.find(([name]) => name === "record_proof_run")?.[1];
it.each([0, 1])("records ran/reproduced (%i), uses the observed owner and never the hosted environment", async n => {
  leak = n; await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_user: user, p_job: id, p_token: id, p_outcome: n ? "reproduced" : "ran", p_reason: null });
  expect(m.run.mock.calls.some(([, sql]) => sql.includes('"owner_id"'))).toBe(true);
  expect(m.run.mock.calls.some(([, sql]) => sql.includes('"user_id"'))).toBe(false);
  expect(m.close).toHaveBeenCalledOnce(); expect(m.hosted).not.toHaveBeenCalled();
  expect(m.db).toHaveBeenCalledWith(user, repo);
});
it.each(["missing", "other_table", "archived"])("refuses finding mismatch %s before opening the host", async kind => {
  rows.deep_findings = kind === "missing" ? null : { finding_id: "f", blast_radius: kind === "other_table" ? "other" : "orders", archived_at: kind === "archived" ? "2026-01-01" : null };
  await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_outcome: "could_not_test", p_reason: "finding_mismatch" });
  expect(m.host).not.toHaveBeenCalled();
  expect(m.filters).toHaveBeenCalledWith("deep_findings", "user_id", user);
  expect(m.filters).toHaveBeenCalledWith("deep_findings", "repository_id", repo);
});
it("reports no owner column rather than inventing one", async () => {
  m.db.mockResolvedValue({ admission: "connection-matched", snapshots: { directPostgresSnapshot: { policies: [policy], columns: [] } } });
  await executeProofJob(job); expect(recorded().p_reason).toBe("no_owner_column"); expect(m.host).not.toHaveBeenCalled();
});
it("refuses ambiguous or unbound database evidence", async () => {
  m.db.mockResolvedValue({ admission: "unknown", snapshots: {} });
  await executeProofJob(job); expect(recorded().p_reason).toBe("database_unread"); expect(m.host).not.toHaveBeenCalled();
});
it("control failure is could_not_test, never ran", async () => {
  control = 0; await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "could_not_test", p_reason: "control_failed" });
  expect(m.close).toHaveBeenCalledOnce();
});
it("aborts at the statement budget, permits teardown and closes the host", async () => {
  budget = 8; await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "statement_budget" });
  expect(recorded().p_statements).toBeLessThanOrEqual(budget);
  expect(m.run.mock.calls.some(([, sql]) => sql.startsWith("drop schema"))).toBe(true);
  expect(m.close).toHaveBeenCalledOnce();
});
it("records replica errors as aborted and tears down", async () => {
  m.run.mockImplementation(async (_ref, sql: string) => { if (/as visible/.test(sql)) throw new Error("embedded_replica_timeout"); return []; });
  await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "time_limit" });
  expect(m.close).toHaveBeenCalledOnce();
});
it("records no-arena refusal without a false pass", async () => {
  m.db.mockResolvedValue({ admission: "connection-matched", snapshots: { directPostgresSnapshot: { policies: [], columns: [{ table: "orders", column: "owner_id", type: "uuid" }] } } });
  await executeProofJob(job); expect(recorded().p_outcome).toBe("could_not_test");
});
it("honors the kill switch and does not rerun recorded work", async () => {
  rows.user_profiles = { proving_ground_enabled: true, autonomy_kill_switch: true };
  await executeProofJob(job); expect(recorded().p_reason).toBe("kill_switch"); expect(m.host).not.toHaveBeenCalled();
  m.rpc.mockClear(); rows.proof_runs = { id: 1 }; await executeProofJob(job);
  expect(m.rpc).not.toHaveBeenCalled();
});
it("retries a refused outcome record after cleanup", async () => {
  m.rpc.mockResolvedValue({ error: { message: "lease lost" } });
  await expect(executeProofJob(job)).rejects.toThrow("Proof outcome could not be recorded");
  expect(m.close).toHaveBeenCalledOnce();
});
// Claude, Q6: paths the WIP tests did not cover.
it("aborts when the budget runs out during setup, which openArena would otherwise report as a setup failure", async () => {
  budget = 3; await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "statement_budget" });
  expect(recorded().p_statements).toBeLessThanOrEqual(3);
  expect(m.close).toHaveBeenCalledOnce();
});
it("records the replica's temp-file limit as aborted", async () => {
  m.run.mockImplementation(async (_ref, sql: string) => { if (/as visible/.test(sql)) throw new Error("temporary file size exceeds temp_file_limit (65536kB)"); return []; });
  await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "resource_limit" });
});
it("records a resource-limit crash as aborted, not as a finding or a crash", async () => {
  m.run.mockImplementation(async (_ref, sql: string) => { if (/as visible/.test(sql)) throw new Error("Worker terminated due to reaching memory limit: JS heap out of memory"); return []; });
  await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "resource_limit" });
  expect(m.close).toHaveBeenCalledOnce();
});
it("records a replica SQL error as could_not_test, never ran", async () => {
  m.run.mockImplementation(async (_ref, sql: string) => { if (/as visible/.test(sql)) throw new Error("syntax error at or near"); return []; });
  await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "could_not_test", p_reason: "replica_error" });
});
it.each([
  ["repository_unselected", () => { rows.repositories = { selected: false }; }],
  ["not_enabled", () => { rows.user_profiles = { proving_ground_enabled: false, autonomy_kill_switch: false }; }],
  ["columns_unread", () => { m.db.mockResolvedValue({ admission: "connection-matched", snapshots: { directPostgresSnapshot: { policies: [policy] } } }); }],
] as const)("refuses %s before opening the host", async (reason, arrange) => {
  arrange(); await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_outcome: "could_not_test", p_reason: reason }); expect(m.host).not.toHaveBeenCalled();
});
it("records a cleared fixed probe as ran, with no model leg", async () => {
  await executeProofJob(job);
  expect(recorded()).toMatchObject({ p_outcome: "ran" });
});
it("claims only proof jobs and registers after repair", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync("lib/jobs/worker.ts", "utf8");
  expect(src.indexOf("runNextProofJob()")).toBeGreaterThan(src.indexOf("runNextRepairJob()"));
  expect(src.indexOf("runNextProofJob()")).toBeLessThan(src.indexOf("runNextAuditJob()"));
});
it("still tears down when setup used the whole budget", async () => {
  budget = 7; await executeProofJob(job); // setup is exactly seven statements
  expect(recorded()).toMatchObject({ p_outcome: "aborted", p_reason: "statement_budget", p_statements: 7 });
  expect(m.run.mock.calls.some(([, sql]) => sql.startsWith("drop schema"))).toBe(true);
});
it("records an unavailable replica as could_not_test instead of leaving the test pending", async () => {
  m.host.mockRejectedValue(new Error("Cannot find module embeddedWorker.mjs"));
  await executeProofJob(job); expect(recorded()).toMatchObject({ p_outcome: "could_not_test", p_reason: "replica_unavailable" });
});
it("retries a failed read instead of recording a permanent outcome", async () => {
  m.read.mockImplementation(async (table: string) => table === "deep_findings" ? { data: null, error: { message: "timeout" } }
    : { data: table === "proof_authorizations" ? { id: authorization, user_id: user, repository_id: repo, finding_id: "f", table_name: "public.orders", target_kind: "replica", status: "consumed", statement_budget: 60 } : rows[table], error: null });
  await expect(executeProofJob(job)).rejects.toThrow("Proof finding could not be read");
  expect(recorded()).toBeUndefined(); expect(m.host).not.toHaveBeenCalled();
});

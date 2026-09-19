import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  reads: { user_profiles: vi.fn(), repositories: vi.fn(), audit_runs: vi.fn() },
  filters: vi.fn(), runAudit: vi.fn(), claim: vi.fn(), execute: vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof state.reads) => {
  const query = { eq: (key: string, value: unknown) => { state.filters(table,key,value); return query; },
    maybeSingle: () => state.reads[table]() };
  return { select: () => query };
} }) }));
vi.mock("@/lib/agent/audit", () => ({ runRepositoryAudit: state.runAudit }));
vi.mock("./queue", () => {
  class PermanentJobError extends Error {}
  return { PermanentJobError, claimJob: state.claim, executeClaimedJob: state.execute };
});

import { executeAuditJob, runNextAuditJob } from "./auditWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id:"11111111-1111-4111-8111-111111111111", user_id:"22222222-2222-4222-8222-222222222222",
  repository_id:"33333333-3333-4333-8333-333333333333", audit_run_id:"44444444-4444-4444-8444-444444444444",
  kind:"audit",status:"running",attempts:1,lease_token:"55555555-5555-4555-8555-555555555555",
  lease_until:"2099-01-01T00:00:00Z",checkpoint:0,
};

beforeEach(() => {
  vi.clearAllMocks();
  state.reads.user_profiles.mockResolvedValue({data:{github_installation_id:42,supabase_mgmt_token_encrypted:"cipher",postgres_dsn_encrypted:null},error:null});
  state.reads.repositories.mockResolvedValue({data:{full_name:"acme/app",selected:true},error:null});
  state.reads.audit_runs.mockResolvedValue({data:{full_name:"acme/app",status:"queued"},error:null});
  state.runAudit.mockResolvedValue({});
});

it("re-reads current tenant context and executes the queue-created run", async () => {
  await executeAuditJob(job);
  expect(state.runAudit).toHaveBeenCalledWith({userId:job.user_id,installationId:42,repositoryId:job.repository_id,
    fullName:"acme/app",trigger:"manual",hasDatabase:true,runId:job.audit_run_id,
    jobLease:{jobId:job.id,token:job.lease_token}});
  expect(state.filters).toHaveBeenCalledWith("repositories","user_id",job.user_id);
  expect(state.filters).toHaveBeenCalledWith("audit_runs","repository_id",job.repository_id);
});

it("treats an already-complete run as the durable acknowledgement", async () => {
  state.reads.audit_runs.mockResolvedValue({data:{full_name:"acme/app",status:"complete"},error:null});
  await executeAuditJob(job); expect(state.runAudit).not.toHaveBeenCalled();
});

it("permanently refuses changed or malformed tenant context", async () => {
  state.reads.repositories.mockResolvedValue({data:{full_name:"other/app",selected:true},error:null});
  await expect(executeAuditJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.runAudit).not.toHaveBeenCalled();
});

it("retries storage failures without logging or embedding provider details", async () => {
  state.reads.user_profiles.mockResolvedValue({data:null,error:{message:"private"}});
  await expect(executeAuditJob(job)).rejects.toThrow("Audit context could not be read");
});

it("claims at most one audit invocation", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextAuditJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job); state.execute.mockResolvedValueOnce(undefined);
  expect(await runNextAuditJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job,[executeAuditJob]);
});

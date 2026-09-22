import { beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";

const state = vi.hoisted(() => ({
  reads: { user_profiles: vi.fn(), repositories: vi.fn(), pull_request_jobs: vi.fn() },
  filters: vi.fn(), runCheck: vi.fn(), claim: vi.fn(), execute: vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof state.reads) => {
  const query = { eq: (key: string, value: unknown) => { state.filters(table,key,value); return query; },
    maybeSingle: () => state.reads[table]() };
  return { select: () => query };
} }) }));
vi.mock("@/lib/agent/prCheck", () => ({ runPullRequestCheck: state.runCheck }));
vi.mock("./queue", () => {
  class PermanentJobError extends Error {}
  return { PermanentJobError, claimJob: state.claim, executeClaimedJob: state.execute,
    JobKind: z.enum(["audit","source","monitor","dependency","graph","pr-check"]) };
});

import { executePullRequestCheckJob, runNextPullRequestCheckJob } from "./prCheckWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id:"11111111-1111-4111-8111-111111111111", user_id:"22222222-2222-4222-8222-222222222222",
  repository_id:"33333333-3333-4333-8333-333333333333", audit_run_id:null, kind:"pr-check",
  deduplication_key:"pr-check:test",status:"running",attempts:1,lease_token:"55555555-5555-4555-8555-555555555555",
  lease_until:"2099-01-01T00:00:00Z",checkpoint:0,
};

beforeEach(() => {
  vi.clearAllMocks();
  state.reads.user_profiles.mockResolvedValue({data:{github_installation_id:42},error:null});
  state.reads.repositories.mockResolvedValue({data:{full_name:"acme/app",selected:true},error:null});
  state.reads.pull_request_jobs.mockResolvedValue({data:{user_id:job.user_id,repository_id:job.repository_id,pull_request_number:7,head_sha:"a".repeat(40)},error:null});
  state.runCheck.mockResolvedValue({posted:true,verdict:"pass",findings:0});
});

it("re-reads current tenant context and runs exactly the stored PR head", async () => {
  await executePullRequestCheckJob(job);
  expect(state.runCheck).toHaveBeenCalledWith({userId:job.user_id,installationId:42,fullName:"acme/app",prNumber:7,headSha:"a".repeat(40)});
  expect(state.filters).toHaveBeenCalledWith("repositories","user_id",job.user_id);
  expect(state.filters).toHaveBeenCalledWith("pull_request_jobs","job_id",job.id);
});

it("permanently refuses missing, deselected, or cross-tenant context", async () => {
  state.reads.repositories.mockResolvedValue({data:{full_name:"acme/app",selected:false},error:null});
  await expect(executePullRequestCheckJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.runCheck).not.toHaveBeenCalled();
});

it("retries storage failures", async () => {
  state.reads.pull_request_jobs.mockResolvedValue({data:null,error:{message:"private"}});
  await expect(executePullRequestCheckJob(job)).rejects.toThrow("context could not be read");
});

it("claims at most one PR check", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextPullRequestCheckJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job); state.execute.mockResolvedValueOnce(undefined);
  expect(await runNextPullRequestCheckJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job,[executePullRequestCheckJob]);
});

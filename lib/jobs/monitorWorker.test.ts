import { beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";
import type { Finding } from "@/lib/monitoring/findings";

const state = vi.hoisted(() => ({
  reads: { monitoring_job_context: vi.fn(), user_profiles: vi.fn() },
  filters: vi.fn(), run: vi.fn(), claim: vi.fn(), execute: vi.fn(),rpc:vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc:state.rpc,from: (table: keyof typeof state.reads) => {
  const query = { eq: (key: string, value: unknown) => { state.filters(table,key,value); return query; },
    maybeSingle: () => state.reads[table]() };
  return { select: () => query };
} }) }));
vi.mock("@/lib/monitoring/run", () => ({ runMonitoringPassForWorker: state.run }));
vi.mock("./queue", () => { class PermanentJobError extends Error {} return {
  PermanentJobError, claimJob: state.claim, executeClaimedJob: state.execute,
  withLeaseHeartbeat: (_job: unknown, work: () => Promise<unknown>) => work(),
  JobKind: z.enum(["audit","source","monitor","dependency","graph","pr-check"]),
}; });

import { executeMonitorJob, runNextMonitorJob } from "./monitorWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id:"11111111-1111-4111-8111-111111111111", user_id:"22222222-2222-4222-8222-222222222222",
  repository_id:null,audit_run_id:null,deduplication_key:"scheduled-monitor:test",kind:"monitor",
  status:"running",attempts:1,lease_token:"33333333-3333-4333-8333-333333333333",
  lease_until:"2099-01-01T00:00:00Z",checkpoint:0,
};
const providerOnly = {
  id:job.user_id,email:"founder@example.com",monitoring_enabled:false,
  monitored_project_url:null,monitored_anon_key_encrypted:null,monitored_app_url:null,
  postgres_dsn_encrypted:"cipher",vercel_access_token_encrypted:null,vercel_team_id:null,
  supabase_mgmt_token_encrypted:null,supabase_mgmt_project_ref:null,
};

beforeEach(() => {
  vi.clearAllMocks();
  state.reads.monitoring_job_context.mockResolvedValue({data:{user_id:job.user_id,trigger_source:"scheduled_48h"},error:null});
  state.reads.user_profiles.mockResolvedValue({data:providerOnly,error:null});
  state.run.mockResolvedValue({newFindingsCount:0,newFindings:[],writesSucceeded:true});
  state.rpc.mockResolvedValue({data:true,error:null});
});

it("runs a provider-only customer from current database context", async () => {
  await executeMonitorJob(job);
  expect(state.run).toHaveBeenCalledWith({ ...providerOnly, email: null },"scheduled_48h");
  expect(state.filters).toHaveBeenCalledWith("monitoring_job_context","job_id",job.id);
  expect(state.filters).toHaveBeenCalledWith("user_profiles","id",job.user_id);
});

it("permanently refuses disconnected, cross-tenant, or hourly provider-only context", async () => {
  state.reads.user_profiles.mockResolvedValueOnce({data:{...providerOnly,postgres_dsn_encrypted:null},error:null});
  await expect(executeMonitorJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  state.reads.user_profiles.mockResolvedValueOnce({data:{...providerOnly,monitoring_enabled:true,postgres_dsn_encrypted:null},error:null});
  await expect(executeMonitorJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  state.reads.monitoring_job_context.mockResolvedValueOnce({data:{user_id:"44444444-4444-4444-8444-444444444444",trigger_source:"scheduled_48h"},error:null});
  await expect(executeMonitorJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  state.reads.monitoring_job_context.mockResolvedValueOnce({data:{user_id:job.user_id,trigger_source:"hourly"},error:null});
  await expect(executeMonitorJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.run).not.toHaveBeenCalled();
});

it("retries storage and provider failures", async () => {
  state.reads.monitoring_job_context.mockResolvedValueOnce({data:null,error:{message:"private"}});
  await expect(executeMonitorJob(job)).rejects.toThrow("could not be read");
  state.run.mockRejectedValueOnce(new Error("provider unavailable"));
  await expect(executeMonitorJob(job)).rejects.toThrow("provider unavailable");
});

it("admits fresh alerts before retrying a failed coverage write",async()=>{
  const fresh=[{id:"rls:orders",severity:"CRITICAL",title:"Open orders",consequence:"Anyone can read."}];
  state.run.mockResolvedValueOnce({newFindingsCount:1,newFindings:fresh,writesSucceeded:false});
  await expect(executeMonitorJob(job)).rejects.toThrow("coverage could not be stored");
  expect(state.rpc).toHaveBeenCalledWith("enqueue_monitoring_notifications",expect.objectContaining({p_findings:fresh}));
});

it("bounds large alert batches without dropping later critical findings",async()=>{
  const many:Finding[]=Array.from({length:101},(_,index)=>({
    id:`warning:${index}`,severity:"WARNING" as const,title:`Warning ${index}`,consequence:"Review it.",
  }));
  many.push({id:"critical:last",severity:"CRITICAL",title:"Critical",consequence:"Act now."});
  state.run.mockResolvedValueOnce({newFindingsCount:many.length,newFindings:many,writesSucceeded:true});
  await executeMonitorJob(job);
  const call=state.rpc.mock.calls.find(([name])=>name==="enqueue_monitoring_notifications");
  const batch=call?.[1].p_findings as typeof many;
  expect(batch).toHaveLength(100);
  expect(batch.some((finding)=>finding.id==="critical:last")).toBe(true);
  expect(batch.at(-1)?.id).toBe(`monitoring:additional-findings:${job.id}`);
});

it("bounds alert payload bytes as well as finding count",async()=>{
  const many=Array.from({length:20},(_,index)=>({
    id:`large:${index}`,severity:"WARNING" as const,title:`Large ${index}`,consequence:"x".repeat(20_000),
  }));
  state.run.mockResolvedValueOnce({newFindingsCount:many.length,newFindings:many,writesSucceeded:true});
  await executeMonitorJob(job);
  const call=state.rpc.mock.calls.find(([name])=>name==="enqueue_monitoring_notifications");
  const batch=call?.[1].p_findings as typeof many;
  expect(Buffer.byteLength(JSON.stringify(batch),"utf8")).toBeLessThanOrEqual(240*1024);
  expect(batch.at(-1)?.id).toBe(`monitoring:additional-findings:${job.id}`);
});

it("fences the hourly fairness receipt even when its provider attempt fails",async()=>{
  state.reads.monitoring_job_context.mockResolvedValue({data:{user_id:job.user_id,trigger_source:"hourly"},error:null});
  state.reads.user_profiles.mockResolvedValue({data:{...providerOnly,monitoring_enabled:true,postgres_dsn_encrypted:null,monitored_project_url:"https://x.supabase.co",monitored_anon_key_encrypted:"cipher"},error:null});
  state.run.mockRejectedValue(new Error("provider unavailable"));
  await expect(executeMonitorJob(job)).rejects.toThrow("provider unavailable");
  expect(state.rpc).toHaveBeenCalledWith("stamp_hourly_monitor_attempt",{p_user:job.user_id,p_job:job.id,p_token:job.lease_token});
});

it("claims at most one monitor job", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextMonitorJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job);state.execute.mockResolvedValueOnce(undefined);
  expect(await runNextMonitorJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job,[executeMonitorJob]);
});

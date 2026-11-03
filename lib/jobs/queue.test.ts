import { beforeEach, expect, it, vi } from "vitest";
const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));
import { enqueueAuditJob, enqueueJob, enqueuePullRequestCheck, enqueuePullRequestIntelligence, claimJob, executeClaimedJob, withLeaseHeartbeat, type ClaimedJob } from "./queue";
const id = "11111111-1111-4111-8111-111111111111";
const job: ClaimedJob = { id, user_id: id, repository_id: id, kind: "audit", status: "running", attempts: 1,
  audit_run_id: "33333333-3333-4333-8333-333333333333", deduplication_key: "audit:test",
  lease_token: "22222222-2222-4222-8222-222222222222", lease_until: "2099-01-01T00:00:00Z", checkpoint: 0 };
beforeEach(() => { rpc.mockReset().mockResolvedValue({ data: true, error: null }); });
it("queues only bounded identity fields and requires a persisted receipt", async () => {
  rpc.mockResolvedValue({ data: id, error: null });
  expect(await enqueueJob(id,id,"monitor","scheduled:window")).toBe(id);
  expect(rpc).toHaveBeenCalledWith("enqueue_execution_job", { p_user:id,p_repository:id,p_kind:"monitor",p_key:"scheduled:window" });
  rpc.mockResolvedValue({ data: null, error: { message: "private" } });
  await expect(enqueueJob(id,id,"monitor","next")).rejects.toThrow("Work could not be queued");
  await expect(enqueueJob(id,id,"audit","wrong-entrypoint")).rejects.toThrow("enqueueAuditJob");
});
it("queues the audit and customer-visible run as one receipt", async () => {
  const run="33333333-3333-4333-8333-333333333333";
  rpc.mockResolvedValue({ data: [{ job_id:id, run_id:run }], error:null });
  expect(await enqueueAuditJob(id,id,"manual:request-id")).toEqual({job_id:id,run_id:run});
  expect(rpc).toHaveBeenCalledWith("enqueue_repository_audit",{p_user:id,p_repository:id,p_key:"manual:request-id",p_trigger:"manual"});
  await enqueueAuditJob(id,id,"pull-request:sha","pull_request");
  expect(rpc).toHaveBeenLastCalledWith("enqueue_repository_audit",{p_user:id,p_repository:id,p_key:"pull-request:sha",p_trigger:"pull_request"});
  await expect(enqueueAuditJob(id,id,"bad","deploy" as never)).rejects.toThrow();
});
it("queues only typed pull-request identity context", async () => {
  rpc.mockResolvedValue({ data:id,error:null });
  expect(await enqueuePullRequestCheck(id,id,"pr-check:head",7,"ABC1234")).toBe(id);
  expect(rpc).toHaveBeenCalledWith("enqueue_pull_request_check",{
    p_user:id,p_repository:id,p_key:"pr-check:head",p_pull_request_number:7,p_head_sha:"abc1234",
  });
  await expect(enqueuePullRequestCheck(id,id,"bad",0,"not-sha")).rejects.toThrow();
});
it.each([[], [job], [{ ...job, lease_token: null }], [{ ...job, kind:"source" }], [job,job]].map((data) => ({ data })))("validates claimed work", async ({ data }) => {
  rpc.mockResolvedValue({ data, error:null });
  if (!data.length) expect(await claimJob("audit")).toBeNull();
  else if (data.length===1 && data[0]===job) expect(await claimJob("audit")).toEqual(job);
  else await expect(claimJob("audit")).rejects.toThrow();
});
it("resumes at the durable checkpoint without rerunning earlier stages", async () => {
  const first=vi.fn(), second=vi.fn().mockResolvedValue(undefined);
  await executeClaimedJob({ ...job,checkpoint:1 },[first,second]);
  expect(first).not.toHaveBeenCalled(); expect(second).toHaveBeenCalledOnce();
  expect(rpc.mock.calls.map(([,args])=>[args.p_checkpoint,args.p_outcome])).toEqual([[1,"heartbeat"],[2,"checkpoint"],[2,"succeeded"]]);
});
it("a failed stage retries without advancing its checkpoint or running later work", async () => {
  const later=vi.fn();
  await expect(executeClaimedJob(job,[async()=>{throw new Error("stage");},later])).rejects.toThrow("stage");
  expect(later).not.toHaveBeenCalled();
  expect(rpc.mock.calls.map(([,args])=>args.p_outcome)).toEqual(["heartbeat","retry"]);
});
it("permanent context failures become dead jobs rather than repeated retries", async () => {
  const { PermanentJobError } = await import("./queue");
  await expect(executeClaimedJob(job,[async()=>{throw new PermanentJobError("changed");}])).rejects.toThrow("changed");
  expect(rpc.mock.calls.map(([,args])=>args.p_outcome)).toEqual(["heartbeat","dead"]);
});
it("a job whose repository was deselected ends cancelled and the wake answers normally", async () => {
  const { StaleJobError } = await import("./queue");
  await expect(executeClaimedJob(job,[async()=>{throw new StaleJobError("deselected");}])).resolves.toBeUndefined();
  expect(rpc.mock.calls.map(([,args])=>args.p_outcome)).toEqual(["heartbeat","cancelled"]);
});
it("lease rejection prevents stage entry", async () => {
  rpc.mockResolvedValue({data:false,error:null}); const stage=vi.fn();
  await expect(executeClaimedJob(job,[stage])).rejects.toThrow("Work lease lost"); expect(stage).not.toHaveBeenCalled();
});
it("uncertain checkpoint acknowledgement cannot complete or start the next stage", async () => {
  rpc.mockResolvedValueOnce({data:true,error:null}).mockResolvedValue({data:null,error:{message:"lost reply"}});
  const next=vi.fn(); await expect(executeClaimedJob(job,[async()=>{},next])).rejects.toThrow();
  expect(next).not.toHaveBeenCalled(); expect(rpc.mock.calls.some(([,args])=>args.p_outcome==="succeeded")).toBe(false);
});
it("keeps a long provider read inside the live lease", async () => {
  vi.useFakeTimers();
  try {
    let release!: () => void;
    const work = new Promise<void>((resolve) => { release = resolve; });
    const running = withLeaseHeartbeat(job, () => work);
    await vi.advanceTimersByTimeAsync(45_000);
    expect(rpc).toHaveBeenCalledWith("advance_execution_job", {
      p_id: job.id,
      p_token: job.lease_token,
      p_checkpoint: job.checkpoint,
      p_outcome: "heartbeat",
    });
    release();
    await running;
  } finally {
    vi.useRealTimers();
  }
});

it("queues an every-PR intelligence scan only at a full head commit, and reports no approval as null", async () => {
  rpc.mockResolvedValue({ data: id, error: null });
  expect(await enqueuePullRequestIntelligence(id, id, 7, "A".repeat(40))).toBe(id);
  expect(rpc).toHaveBeenCalledWith("enqueue_pull_request_intelligence", { p_user: id, p_repository: id, p_pr: 7, p_head: "a".repeat(40) });
  rpc.mockResolvedValue({ data: null, error: null });
  expect(await enqueuePullRequestIntelligence(id, id, 7, "a".repeat(40))).toBeNull();
  await expect(enqueuePullRequestIntelligence(id, id, 7, "abc1234")).rejects.toThrow();
  rpc.mockResolvedValue({ data: null, error: { message: "private" } });
  await expect(enqueuePullRequestIntelligence(id, id, 7, "a".repeat(40))).rejects.toThrow("could not be queued");
});

it("reports the manual audit quota distinctly so the customer can be told", async () => {
  rpc.mockResolvedValue({ data: null, error: { message: "audit quota reached" } });
  await expect(enqueueAuditJob(id, id, "manual:x")).rejects.toThrow("audit_quota_reached");
  rpc.mockResolvedValue({ data: null, error: { message: "private detail" } });
  await expect(enqueueAuditJob(id, id, "manual:y")).rejects.toThrow("Audit could not be queued");
});

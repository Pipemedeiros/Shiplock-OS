import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ auth: vi.fn(), profile: vi.fn(), repository: vi.fn(), filters: vi.fn(),
  enqueue: vi.fn(), worker: vi.fn(), after: vi.fn(), supersede: vi.fn() }));
vi.mock("next/server", async (original) => ({ ...(await original<typeof import("next/server")>()), after: mocks.after }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.auth }));
vi.mock("@/lib/jobs/queue", () => ({ enqueueAuditJob: mocks.enqueue, supersedeStaleAudits: mocks.supersede }));
vi.mock("@/lib/jobs/auditWorker", () => ({ runNextAuditJob: mocks.worker }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const query = { eq: (key: string,value: unknown) => { mocks.filters(table,key,value); return query; },
    single: mocks.profile, maybeSingle: mocks.repository };
  return { select: () => query };
} }) }));

import { POST } from "./route";
const user="11111111-1111-4111-8111-111111111111", repo="22222222-2222-4222-8222-222222222222";
const run="33333333-3333-4333-8333-333333333333", job="44444444-4444-4444-8444-444444444444";
const request = (body: unknown) => new Request("https://shiplock.test/api/audit",{method:"POST",headers:{"content-type":"application/json",origin:"https://shiplock.test"},body:JSON.stringify(body)});

beforeEach(() => {
  vi.clearAllMocks(); mocks.auth.mockResolvedValue({userId:user});
  mocks.profile.mockResolvedValue({data:{github_installation_id:42},error:null});
  mocks.repository.mockResolvedValue({data:{id:repo,full_name:"acme/app"},error:null});
  mocks.enqueue.mockResolvedValue({job_id:job,run_id:run}); mocks.worker.mockResolvedValue(true);
  mocks.after.mockImplementation(() => undefined); mocks.supersede.mockResolvedValue(3);
});

it("returns one durable run receipt and schedules its worker after the response", async () => {
  const requestId="55555555-5555-4555-8555-555555555555";
  const response=await POST(request({repository:"acme/app",requestId}));
  expect(response.status).toBe(202); expect(await response.json()).toEqual({runId:run,status:"queued"});
  expect(mocks.enqueue).toHaveBeenCalledWith(user,repo,`manual:${requestId}`);
  expect(mocks.after).toHaveBeenCalledOnce();
  await mocks.after.mock.calls[0][0](); expect(mocks.worker).toHaveBeenCalledOnce();
});

it("rejects requests before queue mutation when identity or repository admission fails", async () => {
  mocks.auth.mockResolvedValueOnce(null);
  expect((await POST(request({repository:"acme/app"}))).status).toBe(401);
  expect((await POST(request({repository:"not a repo"}))).status).toBe(400);
  mocks.profile.mockResolvedValueOnce({data:{github_installation_id:null},error:null});
  expect((await POST(request({repository:"acme/app"}))).status).toBe(409);
  mocks.repository.mockResolvedValueOnce({data:null,error:null});
  expect((await POST(request({repository:"acme/app"}))).status).toBe(404);
  expect(mocks.enqueue).not.toHaveBeenCalled();
});

it("keeps queue failures generic and does not start an unrecorded worker", async () => {
  vi.spyOn(console,"error").mockImplementation(() => {});
  mocks.enqueue.mockRejectedValue(new Error("private database detail"));
  const response=await POST(request({repository:"acme/app"}));
  expect(response.status).toBe(503); expect(await response.json()).toEqual({error:"The audit could not be queued."});
  expect(mocks.after).not.toHaveBeenCalled();
});

it("tells the customer plainly when the daily manual audit limit is reached (3H-1)", async () => {
  mocks.enqueue.mockRejectedValue(new Error("audit_quota_reached"));
  const response = await POST(request({repository:"acme/app"}));
  expect(response.status).toBe(429);
  expect((await response.json()).error).toMatch(/20 audits in the last 24 hours/);
  expect(mocks.after).not.toHaveBeenCalled();
});

// 097 (2026-10-01): older queued audits of the repository are replaced before
// the worker runs, so the click runs the audit just requested, not a stale one.
it("replaces older queued audits before running the worker", async () => {
  await POST(request({repository:"acme/app",requestId:"66666666-6666-4666-8666-666666666666"}));
  await mocks.after.mock.calls[0][0]();
  expect(mocks.supersede).toHaveBeenCalledOnce();
  expect(mocks.supersede.mock.invocationCallOrder[0]).toBeLessThan(mocks.worker.mock.invocationCallOrder[0]);
});

it("still runs the worker when replacing stale audits fails", async () => {
  mocks.supersede.mockRejectedValue(new Error("db"));
  await POST(request({repository:"acme/app",requestId:"77777777-7777-4777-8777-777777777777"}));
  await mocks.after.mock.calls[0][0]();
  expect(mocks.worker).toHaveBeenCalledOnce();
});

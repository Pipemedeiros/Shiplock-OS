import {beforeEach,expect,it,vi} from "vitest";
const state=vi.hoisted(()=>({user:vi.fn(),profile:vi.fn(),repositories:vi.fn(),enqueue:vi.fn(),worker:vi.fn()}));
const afterWork:Promise<unknown>[]=[];
vi.mock("next/server",async()=>{const actual=await vi.importActual<typeof import("next/server")>("next/server");return {...actual,after:(fn:()=>unknown)=>afterWork.push(Promise.resolve().then(fn))};});
vi.mock("@/lib/deep/proGate",()=>({requireProUser:state.user}));
vi.mock("@/lib/jobs/queue",()=>({enqueueJob:state.enqueue}));
vi.mock("@/lib/jobs/worker",()=>({runNextJob:state.worker}));
vi.mock("@/lib/supabase",()=>({getSupabaseAdmin:()=>({from:(table:string)=>({select:()=>{
  if(table==="user_profiles")return {eq:()=>({single:state.profile})};
  if(table==="repositories")return {eq:()=>({eq:()=>({limit:state.repositories})})};
  throw new Error("unexpected table");
}})})}));
import {POST} from "./route";

beforeEach(()=>{
  vi.clearAllMocks();afterWork.splice(0);
  state.user.mockResolvedValue({userId:"11111111-1111-4111-8111-111111111111"});
  state.profile.mockResolvedValue({data:{github_installation_id:42},error:null});
  state.repositories.mockResolvedValue({data:[{id:"22222222-2222-4222-8222-222222222222"}],error:null});
  state.enqueue.mockResolvedValue("33333333-3333-4333-8333-333333333333");state.worker.mockResolvedValue(true);
});

it("durably queues selected repository scans and returns before collection",async()=>{
  const response=await POST(new Request("https://shiplock.dev/api/deep/github/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
  expect(response.status).toBe(202);
  await expect(response.json()).resolves.toEqual({ok:true,queued:1});
  expect(state.enqueue).toHaveBeenCalledWith(expect.any(String),"22222222-2222-4222-8222-222222222222","source",expect.stringMatching(/^manual-source:/));
  await Promise.all(afterWork);
  expect(state.worker).toHaveBeenCalledOnce();
});

it("fails closed when any admission cannot be recorded",async()=>{
  state.enqueue.mockRejectedValue(new Error("private"));
  expect((await POST(new Request("https://shiplock.dev/api/deep/github/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }))).status).toBe(503);
  expect(afterWork).toHaveLength(0);
});

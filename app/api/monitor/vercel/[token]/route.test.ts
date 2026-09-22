import { createHash } from "node:crypto";
import { beforeEach, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const enqueue=vi.hoisted(()=>vi.fn());
const profile=vi.hoisted(()=>vi.fn());
vi.mock("@/lib/jobs/scheduler",()=>({enqueueMonitoringPass:enqueue}));
vi.mock("@/lib/supabase",()=>({getSupabaseAdmin:()=>({from:()=>{
  const query={select:()=>query,eq:()=>query,maybeSingle:profile};return query;
}})}));
import { POST } from "./route";

const params={params:Promise.resolve({token:"webhook-token"})};
const request=(body:string)=>new NextRequest("https://shiplock.dev/api/monitor/vercel/webhook-token",{method:"POST",body,headers:{"content-type":"application/json"}});
beforeEach(()=>{vi.clearAllMocks();profile.mockResolvedValue({data:{id:"11111111-1111-4111-8111-111111111111"},error:null});enqueue.mockResolvedValue("job");});

it("admits a production deployment using a replay-stable body hash",async()=>{
  const raw=JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"production",id:"d1"}}});
  expect((await POST(request(raw),params)).status).toBe(200);
  expect(enqueue).toHaveBeenCalledWith("11111111-1111-4111-8111-111111111111","deploy",
    `deploy-monitor:${createHash("sha256").update(raw).digest("hex")}`);
});
it("ignores malformed, non-production, and unknown deliveries",async()=>{
  expect((await POST(request("{"),params)).status).toBe(200);
  expect((await POST(request(JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"preview"}}})),params)).status).toBe(200);
  profile.mockResolvedValueOnce({data:null,error:null});
  expect((await POST(request(JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"production"}}})),params)).status).toBe(200);
  expect(enqueue).not.toHaveBeenCalled();
});
it("lets the queue contract admit a provider-only profile",async()=>{
  profile.mockResolvedValueOnce({data:{id:"11111111-1111-4111-8111-111111111111",monitoring_enabled:false},error:null});
  const response=await POST(request(JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"production"}}})),params);
  expect(response.status).toBe(200);expect(enqueue).toHaveBeenCalledOnce();
});
it("returns 503 so the provider can retry an identity lookup failure",async()=>{
  profile.mockResolvedValueOnce({data:null,error:{message:"private"}});
  const response=await POST(request(JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"production"}}})),params);
  expect(response.status).toBe(503);expect(enqueue).not.toHaveBeenCalled();
});
it("returns 503 so the provider can retry failed admission",async()=>{
  enqueue.mockRejectedValue(new Error("private"));
  const response=await POST(request(JSON.stringify({type:"deployment.ready",payload:{deployment:{target:"production"}}})),params);
  expect(response.status).toBe(503);await expect(response.json()).resolves.toEqual({received:false});
});
it("rejects an oversized delivery before any database lookup",async()=>{
  const response=await POST(request("x".repeat(128*1024+1)),params);
  expect(response.status).toBe(413);
  expect(profile).not.toHaveBeenCalled();
  expect(enqueue).not.toHaveBeenCalled();
});

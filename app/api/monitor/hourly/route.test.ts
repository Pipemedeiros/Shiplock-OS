import { beforeEach, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
const admit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/jobs/scheduler",()=>({admitDueMonitoringPasses:admit}));
import { GET } from "./route";

beforeEach(()=>{vi.clearAllMocks();vi.stubEnv("CRON_SECRET","secret");admit.mockResolvedValue({eligible:5,admitted:4,failed:1,limited:true});});
const request=(secret:string)=>new NextRequest("https://shiplock.dev/api/monitor/hourly",{headers:{authorization:`Bearer ${secret}`}});

it("authenticates before admitting hourly work",async()=>{
  expect((await GET(request("wrong"))).status).toBe(401);expect(admit).not.toHaveBeenCalled();
});
it("returns bounded queue admission without running providers",async()=>{
  const response=await GET(request("secret"));
  await expect(response.json()).resolves.toEqual({checked:5,succeeded:4,failed:1,deferred:true});
  expect(admit).toHaveBeenCalledWith("hourly",expect.any(Date),1_000);
});
it("returns a retryable failure without provider details",async()=>{
  admit.mockRejectedValue(new Error("private"));const response=await GET(request("secret"));
  expect(response.status).toBe(503);await expect(response.json()).resolves.toEqual({error:"Monitoring could not be queued."});
});

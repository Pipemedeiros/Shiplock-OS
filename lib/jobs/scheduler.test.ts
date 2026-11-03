import { beforeEach, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));
import { admitDueIntelligenceScans,admitDueMonitoringPasses,admitDueRepositoryAudits,admitDueRepositoryDependencyChecks,admitDueRepositorySourceScans,enqueueMonitoringPass } from "./scheduler";

beforeEach(() => rpc.mockReset().mockResolvedValue({
  data: { eligible: 2, admitted: 2, failed: 0, limited: false }, error: null,
}));

it("admits one bounded UTC-day batch without provider data", async () => {
  await expect(admitDueRepositoryAudits(new Date("2026-09-21T23:30:00Z"), 1_000)).resolves.toEqual({
    eligible: 2, admitted: 2, failed: 0, limited: false,
  });
  expect(rpc).toHaveBeenCalledWith("enqueue_due_repository_audits", {
    p_cutoff: "2026-09-19T23:30:00.000Z",
    p_day: "2026-09-21",
    p_require_paid: false,
    p_limit: 1_000,
  });
});

it("admits bounded source work with the same freshness window",async()=>{
  await expect(admitDueRepositorySourceScans(new Date("2026-09-22T01:00:00Z"),500)).resolves.toMatchObject({admitted:2});
  expect(rpc).toHaveBeenCalledWith("enqueue_due_repository_sources",{
    p_cutoff:"2026-09-20T01:00:00.000Z",p_day:"2026-09-22",p_limit:500,
  });
});

it("admits bounded daily dependency rechecks",async()=>{
  await expect(admitDueRepositoryDependencyChecks(new Date("2026-09-22T01:00:00Z"),250)).resolves.toMatchObject({admitted:2});
  expect(rpc).toHaveBeenCalledWith("enqueue_due_repository_dependencies",{
    p_day:"2026-09-22",p_limit:250,
  });
});

it("admits bounded monitoring windows and typed deploy work",async()=>{
  await admitDueMonitoringPasses("scheduled_48h",new Date("2026-09-22T01:00:00Z"),250);
  expect(rpc).toHaveBeenCalledWith("enqueue_due_monitoring_passes",{
    p_trigger:"scheduled_48h",p_cutoff:"2026-09-20T01:00:00.000Z",p_window:"2026-09-22",p_limit:250,
  });
  rpc.mockResolvedValueOnce({data:"11111111-1111-4111-8111-111111111111",error:null});
  await expect(enqueueMonitoringPass("22222222-2222-4222-8222-222222222222","deploy","deploy:key"))
    .resolves.toBe("11111111-1111-4111-8111-111111111111");
});

it("rejects malformed receipts and unsafe batch sizes", async () => {
  rpc.mockResolvedValue({ data: { eligible: 2, admitted: 2, failed: 1, limited: false }, error: null });
  await expect(admitDueRepositoryAudits()).rejects.toThrow();
  await expect(admitDueRepositoryAudits(new Date(), 5_001)).rejects.toThrow();
});

it("admits approved intelligence scans for one bounded window",async()=>{
  await expect(admitDueIntelligenceScans(new Date("2026-09-23T01:00:00Z"),250)).resolves.toMatchObject({admitted:2});
  expect(rpc).toHaveBeenCalledWith("enqueue_due_intelligence_scans",{p_now:"2026-09-23T01:00:00.000Z",p_limit:250});
  await expect(admitDueIntelligenceScans(new Date("x"),250)).rejects.toThrow();
});

it("reports the manual recheck quota distinctly",async()=>{
  rpc.mockResolvedValueOnce({data:null,error:{message:"recheck quota reached"}});
  await expect(enqueueMonitoringPass("22222222-2222-4222-8222-222222222222","manual","manual:x")).rejects.toThrow("recheck_quota_reached");
});

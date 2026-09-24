import { beforeEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ pr: vi.fn(), audit: vi.fn(), graph: vi.fn(), source:vi.fn(),dependency:vi.fn(),monitor:vi.fn(),notification:vi.fn(),repair:vi.fn(),intelligence:vi.fn(),proof:vi.fn() }));
vi.mock("./prCheckWorker", () => ({ runNextPullRequestCheckJob: state.pr }));
vi.mock("./auditWorker", () => ({ runNextAuditJob: state.audit }));
vi.mock("./sourceWorker",()=>({runNextSourceJob:state.source}));
vi.mock("./graphWorker",()=>({runNextGraphJob:state.graph}));
vi.mock("./dependencyWorker",()=>({runNextDependencyJob:state.dependency}));
vi.mock("./monitorWorker",()=>({runNextMonitorJob:state.monitor}));
vi.mock("./notificationWorker",()=>({runNextNotificationJob:state.notification}));
vi.mock("./repairWorker",()=>({runNextRepairJob:state.repair}));
vi.mock("./intelligenceWorker",()=>({runNextIntelligenceJob:state.intelligence}));
vi.mock("./proofWorker",()=>({runNextProofJob:state.proof}));
import { runNextJob } from "./worker";

beforeEach(() => { vi.clearAllMocks(); state.pr.mockResolvedValue(false); state.audit.mockResolvedValue(false); state.graph.mockResolvedValue(false); state.source.mockResolvedValue(false);state.dependency.mockResolvedValue(false);state.monitor.mockResolvedValue(false);state.notification.mockResolvedValue(false);state.repair.mockResolvedValue(false);state.intelligence.mockResolvedValue(false);state.proof.mockResolvedValue(false); });
it("prioritizes latency-sensitive PR checks", async () => {
  state.pr.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.audit).not.toHaveBeenCalled();
});
it("delivers admitted notifications before starting more scans",async()=>{
  state.notification.mockResolvedValue(true);expect(await runNextJob()).toBe(true);expect(state.notification).toHaveBeenCalledOnce();expect(state.audit).not.toHaveBeenCalled();
});
it("falls through to repository audits", async () => {
  state.audit.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.audit).toHaveBeenCalledOnce();
});
it("drains graph correlation before more source collection",async()=>{
  state.graph.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.graph).toHaveBeenCalledOnce();
  expect(state.source).not.toHaveBeenCalled();
});
it("drains source work after customer-visible and graph work",async()=>{
  state.source.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.source).toHaveBeenCalledOnce();
});
it("drains dependency rechecks after source collection",async()=>{
  state.dependency.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.dependency).toHaveBeenCalledOnce();
});
it("drains provider monitoring after repository work",async()=>{
  state.monitor.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.monitor).toHaveBeenCalledOnce();
});
it("runs a clicked repair before background scans (3F-C2d)",async()=>{
  state.repair.mockResolvedValue(true);expect(await runNextJob()).toBe(true);expect(state.repair).toHaveBeenCalledOnce();expect(state.audit).not.toHaveBeenCalled();
});
it("creates scheduled intelligence tasks after repository work, before provider monitoring (10B-2c)",async()=>{
  state.intelligence.mockResolvedValue(true);expect(await runNextJob()).toBe(true);
  expect(state.dependency).toHaveBeenCalledOnce();expect(state.monitor).not.toHaveBeenCalled();
});
it("runs a clicked proof after a clicked repair and before audits (Q6)",async()=>{
  state.proof.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.repair).toHaveBeenCalledOnce();expect(state.proof).toHaveBeenCalledOnce();expect(state.audit).not.toHaveBeenCalled();
});

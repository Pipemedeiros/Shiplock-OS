import { beforeEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ pr: vi.fn(), audit: vi.fn(), graph: vi.fn(), source:vi.fn(),dependency:vi.fn() }));
vi.mock("./prCheckWorker", () => ({ runNextPullRequestCheckJob: state.pr }));
vi.mock("./auditWorker", () => ({ runNextAuditJob: state.audit }));
vi.mock("./sourceWorker",()=>({runNextSourceJob:state.source}));
vi.mock("./graphWorker",()=>({runNextGraphJob:state.graph}));
vi.mock("./dependencyWorker",()=>({runNextDependencyJob:state.dependency}));
import { runNextJob } from "./worker";

beforeEach(() => { vi.clearAllMocks(); state.pr.mockResolvedValue(false); state.audit.mockResolvedValue(false); state.graph.mockResolvedValue(false); state.source.mockResolvedValue(false);state.dependency.mockResolvedValue(false); });
it("prioritizes latency-sensitive PR checks", async () => {
  state.pr.mockResolvedValue(true);
  expect(await runNextJob()).toBe(true);
  expect(state.audit).not.toHaveBeenCalled();
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

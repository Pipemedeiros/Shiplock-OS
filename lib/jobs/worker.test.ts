import { beforeEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ pr: vi.fn(), audit: vi.fn() }));
vi.mock("./prCheckWorker", () => ({ runNextPullRequestCheckJob: state.pr }));
vi.mock("./auditWorker", () => ({ runNextAuditJob: state.audit }));
import { runNextJob } from "./worker";

beforeEach(() => { vi.clearAllMocks(); state.pr.mockResolvedValue(false); state.audit.mockResolvedValue(false); });
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

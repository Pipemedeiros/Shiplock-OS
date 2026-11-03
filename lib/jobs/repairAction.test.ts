import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ rpc: vi.fn(), after: vi.fn(), run: vi.fn() }));
vi.mock("next/server", async (original) => ({ ...(await original<typeof import("next/server")>()), after: mocks.after }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));
vi.mock("./repairWorker", () => ({ runNextRepairJob: mocks.run }));

import { AGENT_PRS_OFF, requestAgentRepairAction, requestRepairAction } from "./repairAction";

const receiptId = "66666666-6666-4666-8666-666666666666";
beforeEach(() => {
  vi.clearAllMocks();
  mocks.rpc.mockResolvedValue({ data: receiptId, error: null });
  vi.useFakeTimers({ now: new Date("2026-09-22T10:15:42.000Z"), toFake: ["Date"] });
});

describe("requestRepairAction", () => {
  it("admits one receipt per click and wakes the repair worker", async () => {
    expect(await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "finding-fix-pr", findingId: "scan:x", editedContent: "-- fix" })).toBe(receiptId);
    const [name, args] = mocks.rpc.mock.calls[0];
    expect(name).toBe("request_repair_action");
    expect(args).toMatchObject({ p_user: "u1", p_repository: "r1", p_action: "finding-fix-pr", p_finding: "scan:x", p_edited: "-- fix" });
    expect(args.p_key).toMatch(/^finding-fix-pr:scan:x:[a-f0-9]{16}:2026-09-22T10:15$/);
    expect(mocks.after).toHaveBeenCalledOnce();
    await mocks.after.mock.calls[0][0]();
    expect(mocks.run).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });

  it("gives a changed edit a different key, so it is a new request", async () => {
    await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "finding-fix-pr", findingId: "scan:x", editedContent: "-- a" });
    await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "finding-fix-pr", findingId: "scan:x", editedContent: "-- b" });
    expect(mocks.rpc.mock.calls[0][1].p_key).not.toBe(mocks.rpc.mock.calls[1][1].p_key);
    vi.useRealTimers();
  });

  it("propagates an admission refusal without waking a worker", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "repository unavailable" } });
    await expect(requestRepairAction({ userId: "u1", repositoryId: "r1", action: "risk-fix-pr", findingId: "agent:x", editedContent: null }))
      .rejects.toThrow("could not be queued");
    expect(mocks.after).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  it("binds a fix-before-merge click to its stored review", async () => {
    await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "pr-fix-pr", findingId: "diff:x", editedContent: null, reviewId: "rev-1" });
    expect(mocks.rpc.mock.calls[0][1]).toMatchObject({ p_action: "pr-fix-pr", p_review: "rev-1" });
    vi.useRealTimers();
  });

  it("reports the repair quota distinctly", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "repair quota reached" } });
    await expect(requestRepairAction({ userId: "u1", repositoryId: "r1", action: "dependency-bump-pr", findingId: null, editedContent: null }))
      .rejects.toThrow("repair_quota_reached");
    vi.useRealTimers();
  });

  it("binds an AI-fix click to its intelligence task", async () => {
    await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "ai-fix-pr", findingId: "task-1", editedContent: null, taskId: "task-1" });
    expect(mocks.rpc.mock.calls[0][1]).toMatchObject({ p_action: "ai-fix-pr", p_task: "task-1", p_finding: "task-1", p_review: null });
    vi.useRealTimers();
  });
});

// 103 (Felipe 2026-10-15): the customer's own agent asks for the click's PR.
describe("requestAgentRepairAction", () => {
  it("uses the click's key, so an agent and a click in the same minute share one receipt", async () => {
    await requestAgentRepairAction({ userId: "u1", repositoryId: "r1", findingId: "agent:x" });
    await requestRepairAction({ userId: "u1", repositoryId: "r1", action: "risk-fix-pr", findingId: "agent:x", editedContent: null });
    const [[name, agent], [, click]] = mocks.rpc.mock.calls;
    expect(name).toBe("request_agent_repair_action");
    expect(agent).toEqual({ p_user: "u1", p_repository: "r1", p_finding: "agent:x", p_key: click.p_key });
    expect(mocks.after).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it("says plainly when the customer has not turned agent pull requests on", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "agent pull requests off" } });
    await expect(requestAgentRepairAction({ userId: "u1", repositoryId: "r1", findingId: "agent:x" })).rejects.toThrow(AGENT_PRS_OFF);
    expect(mocks.after).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});

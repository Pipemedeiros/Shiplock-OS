import { describe, it, expect, vi, beforeEach } from "vitest";

const attemptMock = vi.fn();
const deleteMock = vi.fn();
const runOnBranchMock = vi.fn();
vi.mock("./branch", () => ({
  attemptProvingBranch: attemptMock,
  deleteProvingBranch: deleteMock,
  runOnBranch: runOnBranchMock,
}));

const { openArena } = await import("./arena");

const settings = { killSwitchOn: false, provingGroundEnabled: true };
const simplePolicy = {
  schemaname: "public", tablename: "invoices", policyname: "p",
  cmd: "SELECT", qual: "true", with_check: null, roles: ["authenticated"],
};
const complexPolicy = { ...simplePolicy, qual: "(exists (select 1 from memberships m))" };

const request = (over: Record<string, unknown> = {}) => ({
  customerToken: "t", customerRef: "prod", settings,
  table: "invoices", ownerColumn: "user_id", policies: [simplePolicy],
  ...over,
});

const host = (over: Record<string, unknown> = {}) => ({
  token: "ht", projectRef: "proving-ref",
  run: vi.fn().mockResolvedValue([]),
  ...over,
});

describe("arena selection", () => {
  beforeEach(() => {
    attemptMock.mockReset();
    deleteMock.mockReset().mockResolvedValue(true);
    runOnBranchMock.mockReset().mockResolvedValue([]);
  });

  // 6-0: a branch lives on the customer's own, billable project and needs a
  // per-test authorization receipt (6A) that does not exist yet.
  it("never creates a branch on the customer's project", async () => {
    attemptMock.mockResolvedValue({ handle: { ref: "branch-1", target: {} } });
    const { arena } = await openArena(request(), host());
    expect(attemptMock).not.toHaveBeenCalled();
    expect(arena?.kind).toBe("replica");
  });

  it("falls back to a replica when Branching is unavailable", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const h = host();
    const { arena } = await openArena(request(), h);
    expect(arena?.kind).toBe("replica");
    expect(arena?.schema).toMatch(/^proving_/);
    // Setup ran on OUR project, never the customer's.
    expect(h.run).toHaveBeenCalledWith("proving-ref", expect.stringContaining("create schema"));
  });

  it("refuses a replica for a policy it cannot rebuild faithfully", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const { arena, reason } = await openArena(request({ policies: [complexPolicy] }), host());
    expect(arena).toBeNull();
    expect(reason).toContain("queries another table");
  });

  it("returns nothing when no branch and no host", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const { arena, reason } = await openArena(request(), null);
    expect(arena).toBeNull();
    expect(reason).toContain("No proving host");
  });

  it("reports a replica whose setup fails rather than returning a broken arena", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const h = host({ run: vi.fn().mockRejectedValue(new Error("permission denied")) });
    const { arena, reason } = await openArena(request(), h);
    expect(arena).toBeNull();
    expect(reason).toContain("permission denied");
  });
});

describe("teardown", () => {
  beforeEach(() => {
    attemptMock.mockReset();
    deleteMock.mockReset().mockResolvedValue(true);
  });

  it("drops the replica schema", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const h = host();
    const { arena } = await openArena(request(), h);
    await arena!.teardown();
    expect(h.run).toHaveBeenCalledWith("proving-ref", expect.stringContaining("drop schema"));
  });

  it("survives a teardown failure without throwing", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const h = host();
    h.run = vi.fn().mockResolvedValueOnce([]).mockRejectedValue(new Error("gone"));
    const { arena } = await openArena(request(), h);
    await expect(arena!.teardown()).resolves.toBeUndefined();
  });
});

describe("the guard still applies to the replica path", () => {
  it("refuses to run when the kill switch is on, even on our own infrastructure", async () => {
    attemptMock.mockResolvedValue({ handle: null, failure: "plan_required" });
    const { arena } = await openArena(
      request({ settings: { killSwitchOn: true, provingGroundEnabled: true } }),
      host()
    );
    await expect(arena!.run("select 1")).rejects.toThrow(/kill switch/);
  });
});

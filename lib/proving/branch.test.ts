import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { attemptProvingBranch, createProvingBranch, runOnBranch } from "./branch";
import { ProvingGroundViolation } from "./guard";

const settings = { killSwitchOn: false, provingGroundEnabled: true };

describe("createProvingBranch", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("returns a handle flagged as an ephemeral branch with no production data", async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ ref: "branch-1" }) });
    const h = (await createProvingBranch("t", "prod-1"))!;
    expect(h.target.isEphemeralBranch).toBe(true);
    expect(h.target.containsProductionData).toBe(false);
    expect(h.target.parentRef).toBe("prod-1");
  });

  // A second, independent refusal for the case that would be catastrophic.
  it("returns null if the API ever hands back the production ref", async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ ref: "prod-1" }) });
    expect(await createProvingBranch("t", "prod-1")).toBeNull();
  });

  it("fails closed on an error response", async () => {
    fetchMock.mockResolvedValue({ ok: false, json: async () => ({}) });
    expect(await createProvingBranch("t", "prod-1")).toBeNull();
  });

  it("fails closed on a response with no ref", async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ status: "creating" }) });
    expect(await createProvingBranch("t", "prod-1")).toBeNull();
  });

  it("fails closed on a network error", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    expect(await createProvingBranch("t", "prod-1")).toBeNull();
  });
});

describe("runOnBranch", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset().mockResolvedValue({ ok: true, json: async () => [] });
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  // The guard is checked at the point of use, on every statement.
  it("refuses to execute against a target that is not a branch", async () => {
    const handle = {
      ref: "prod-1",
      target: { ref: "prod-1", parentRef: "prod-1", isEphemeralBranch: true, containsProductionData: false },
    };
    await expect(runOnBranch("t", handle, settings, "select 1")).rejects.toThrow(ProvingGroundViolation);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses when the kill switch is on, before any network call", async () => {
    const handle = {
      ref: "branch-1",
      target: { ref: "branch-1", parentRef: "prod-1", isEphemeralBranch: true, containsProductionData: false },
    };
    await expect(
      runOnBranch("t", handle, { ...settings, killSwitchOn: true }, "select 1")
    ).rejects.toThrow(/kill switch/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("executes against a valid branch", async () => {
    const handle = {
      ref: "branch-1",
      target: { ref: "branch-1", parentRef: "prod-1", isEphemeralBranch: true, containsProductionData: false },
    };
    await runOnBranch("t", handle, settings, "select 1");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toContain("branch-1");
  });
});

// Verified against the live Supabase API on 2026-07-30: creating a branch on a
// FREE-plan organisation returns 402 PaymentRequired. That is permanent and
// actionable, unlike a transient failure, and collapsing the two would leave a
// free-plan customer with a feature that never runs and no way to know why.
describe("plan requirement is distinguishable", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("reports plan_required on a 402", async () => {
    fetchMock.mockResolvedValue({ status: 402, ok: false, json: async () => ({}) });
    const a = await attemptProvingBranch("t", "prod-1");
    expect(a.handle).toBeNull();
    expect(a.failure).toBe("plan_required");
  });

  it("reports a generic failure on other errors", async () => {
    fetchMock.mockResolvedValue({ status: 500, ok: false, json: async () => ({}) });
    expect((await attemptProvingBranch("t", "prod-1")).failure).toBe("unavailable");
  });

  it("still fails closed if the API returns the production ref", async () => {
    fetchMock.mockResolvedValue({ status: 200, ok: true, json: async () => ({ ref: "prod-1" }) });
    const a = await attemptProvingBranch("t", "prod-1");
    expect(a.handle).toBeNull();
    expect(a.failure).toBe("unavailable");
  });
});

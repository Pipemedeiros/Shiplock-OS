import { beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { claimFirstScanCredit } from "./firstScanCredit";

const lease = { jobId: "j1", token: "t1" };
beforeEach(() => { rpc.mockReset(); });

describe("first-scan credit (3G-1)", () => {
  it("funds the run only when the durable claim succeeds for this exact run and lease", async () => {
    rpc.mockResolvedValue({ data: true, error: null });
    expect(await claimFirstScanCredit("u1", "run1", lease)).toEqual({ funded: true });
    expect(rpc).toHaveBeenCalledWith("claim_first_scan_credit", { p_user: "u1", p_run: "run1", p_job: "j1", p_token: "t1" });
  });

  it("never funds a used credit, and says why in plain words", async () => {
    rpc.mockResolvedValue({ data: false, error: null });
    const outcome = await claimFirstScanCredit("u1", "run2", lease);
    expect(outcome.funded).toBe(false);
    expect(!outcome.funded && outcome.reason).toMatch(/free AI scan was already used/);
  });

  it("fails closed: no lease or an unreadable claim never spends ShipLock's key", async () => {
    expect((await claimFirstScanCredit("u1", "run1", undefined)).funded).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
    rpc.mockResolvedValue({ data: null, error: { message: "down" } });
    const outcome = await claimFirstScanCredit("u1", "run1", lease);
    expect(outcome.funded).toBe(false);
    expect(!outcome.funded && outcome.reason).toMatch(/could not be confirmed/);
  });
});

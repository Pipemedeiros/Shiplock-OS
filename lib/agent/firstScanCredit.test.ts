import { beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { claimFirstScanCredit } from "./firstScanCredit";

const lease = { jobId: "j1", token: "t1" };
beforeEach(() => { rpc.mockReset(); process.env.SHIPLOCK_FUNDED_FIRST_SCAN = "true"; });

// Felipe (2026-09-29): during the MVP the customer brings the intelligence, so
// ShipLock pays for no model call unless the switch is exactly "true". Off,
// the credit is not touched, so it is still there if funding is turned on.
describe("the funded first scan is off unless switched on", () => {
  for (const value of [undefined, "", "1", "TRUE", "yes"]) {
    it(`does not fund or consume the credit when the switch is ${JSON.stringify(value)}`, async () => {
      if (value === undefined) delete process.env.SHIPLOCK_FUNDED_FIRST_SCAN;
      else process.env.SHIPLOCK_FUNDED_FIRST_SCAN = value;
      rpc.mockResolvedValue({ data: true, error: null });
      const outcome = await claimFirstScanCredit("u1", "run1", lease);
      expect(outcome.funded).toBe(false);
      expect(!outcome.funded && outcome.reason).toMatch(/your own AI/);
      expect(rpc).not.toHaveBeenCalled();
    });
  }
});

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

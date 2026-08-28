import { describe, expect, it } from "vitest";
import { BILLING_ENABLED, hasProductAccess, paidFilterColumn } from "./access";

describe("hasProductAccess", () => {
  it("refuses an account that does not exist, billing on or off", () => {
    // Signing in is not the paywall — it is the condition for reading someone's
    // private source at all. An anonymous caller never gets an audit.
    expect(hasProductAccess(null)).toBe(false);
    expect(hasProductAccess(undefined)).toBe(false);
  });

  it("admits any signed-in account while billing is parked", () => {
    expect(BILLING_ENABLED).toBe(false);
    expect(hasProductAccess({ is_paid: false })).toBe(true);
    expect(hasProductAccess({ is_paid: null })).toBe(true);
    expect(hasProductAccess({})).toBe(true);
  });

  it("drops the paid filter from scheduled passes while billing is parked", () => {
    expect(paidFilterColumn()).toBeNull();
  });
});

import { describe, it, expect } from "vitest";
import { EMPTY_PULSE } from "./pulse";

// The load-bearing property of this panel is honesty: it sits on a paying
// customer's dashboard claiming "we are watching", so it must never render
// activity that didn't happen.
describe("EMPTY_PULSE", () => {
  it("reports no data so the UI renders an empty state, not a fake one", () => {
    expect(EMPTY_PULSE.hasData).toBe(false);
  });

  it("is all zeroes — nothing invented for an unconnected customer", () => {
    expect(EMPTY_PULSE.watched).toBe(0);
    expect(EMPTY_PULSE.sources).toBe(0);
    expect(EMPTY_PULSE.turnedAway).toBe(0);
    expect(EMPTY_PULSE.activeBlocks).toBe(0);
    expect(EMPTY_PULSE.recentPaths).toEqual([]);
    expect(EMPTY_PULSE.buckets.every((b) => b === 0)).toBe(true);
  });

  it("still carries a full bucket array so the chart can render flat", () => {
    expect(EMPTY_PULSE.buckets).toHaveLength(24);
  });

  it("states the window it describes, so the UI never mislabels the period", () => {
    expect(EMPTY_PULSE.windowHours).toBe(48);
  });
});

import { describe, it, expect, vi, afterEach } from "vitest";
import { startPassBudget, createCostEstimator } from "./passBudget";

afterEach(() => {
  vi.useRealTimers();
});

describe("startPassBudget", () => {
  it("admits work while there is room, and stops before the ceiling", () => {
    vi.useFakeTimers();
    // 60s ceiling, 8s reserve => 52s usable.
    const budget = startPassBudget(60_000);

    expect(budget.hasTimeFor(3_000)).toBe(true);

    vi.advanceTimersByTime(50_000);
    // 50s spent, 3s more would exceed the 52s usable window.
    expect(budget.hasTimeFor(3_000)).toBe(false);
    // But a cheap item still fits.
    expect(budget.hasTimeFor(1_000)).toBe(true);
  });

  it("reserves time for post-loop work rather than spending the whole ceiling", () => {
    vi.useFakeTimers();
    const budget = startPassBudget(60_000, 8_000);

    vi.advanceTimersByTime(55_000);
    // Past the usable window even though the raw ceiling has 5s left — that 5s
    // belongs to snapshot writes, digests, and the response.
    expect(budget.hasTimeFor(1)).toBe(false);
  });

  it("tracks how many were deferred, so a truncated pass reports it", () => {
    const budget = startPassBudget(60_000);
    budget.recordSkipped(7);
    budget.recordSkipped(3);
    expect(budget.skippedCount()).toBe(10);
  });

  it("never reports negative usable time when the reserve exceeds the ceiling", () => {
    const budget = startPassBudget(5_000, 8_000);
    expect(budget.hasTimeFor(1)).toBe(false);
    expect(budget.skippedCount()).toBe(0);
  });
});

describe("createCostEstimator", () => {
  it("starts from the seed", () => {
    expect(createCostEstimator(3_000).estimate()).toBe(3_000);
  });

  it("revises upward when a user costs more than expected", () => {
    const cost = createCostEstimator(3_000);
    cost.record(9_000);
    expect(cost.estimate()).toBe(9_000);
  });

  // Deliberately the observed maximum, not a mean: underestimating gets the
  // function killed mid-write, while overestimating merely defers one user to
  // the next run — and the staleness ordering picks them up first.
  it("does not fall back toward the mean after one fast user", () => {
    const cost = createCostEstimator(3_000);
    cost.record(9_000);
    cost.record(500);
    expect(cost.estimate()).toBe(9_000);
  });

  it("ignores a faster-than-seed measurement", () => {
    const cost = createCostEstimator(3_000);
    cost.record(100);
    expect(cost.estimate()).toBe(3_000);
  });
});

describe("budget + estimator together", () => {
  it("stops admitting users once the observed cost makes the next one unsafe", () => {
    vi.useFakeTimers();
    const budget = startPassBudget(60_000); // 52s usable
    const cost = createCostEstimator(3_000);

    // One genuinely slow user resets expectations for the rest of the pass.
    vi.advanceTimersByTime(30_000);
    cost.record(30_000);

    // 30s spent, next one expected to cost 30s => 60s > 52s usable.
    expect(budget.hasTimeFor(cost.estimate())).toBe(false);
  });
});

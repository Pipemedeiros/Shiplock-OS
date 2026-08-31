import { describe, expect, it } from "vitest";
import { AUDIT_BUDGET_MS, REASONING_RESERVE_MS } from "./audit";

/**
 * The time budget, so a large repository finishes rather than being killed.
 *
 * The route runs synchronously inside a serverless function that this plan
 * stops at 60 seconds. Being killed there is the worst available outcome: the
 * audit_runs row is already inserted as "running", so a customer with a big
 * codebase watches a spinner for a function that no longer exists.
 *
 * Measured on real repositories: about 4 seconds of compute even on a
 * 2,359-file monorepo, up to 18 seconds to download its tarball, and 3 to 25
 * seconds for the reasoning call. The download is what varies, so the budget is
 * spent there and reasoning is what gets given up.
 */
describe("audit time budget", () => {
  it("finishes inside the function's own ceiling", () => {
    expect(AUDIT_BUDGET_MS).toBeLessThan(60_000);
  });

  it("reserves more than a real reasoning call takes", () => {
    expect(REASONING_RESERVE_MS).toBeGreaterThanOrEqual(25_000);
    expect(REASONING_RESERVE_MS).toBeLessThan(AUDIT_BUDGET_MS);
  });

  it("still reasons after the slowest ingestion we have measured", () => {
    // If this fails, a large but ordinary repository silently stops getting
    // attack paths, and the only sign is a coverage note.
    const worstIngestionMs = 18_000;
    expect(AUDIT_BUDGET_MS - worstIngestionMs).toBeGreaterThanOrEqual(REASONING_RESERVE_MS);
  });
});

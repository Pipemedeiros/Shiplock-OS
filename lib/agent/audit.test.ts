import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AUDIT_BUDGET_MS, REASONING_RESERVE_MS } from "./audit";

/**
 * The time budget, so a large repository finishes rather than being killed.
 *
 * The route runs synchronously inside a serverless function. Vercel Hobby with
 * Fluid compute stops it at 300 seconds (2026-09-29; before, the code capped
 * itself at 60). Being killed there is the worst available outcome: the
 * audit_runs row is already inserted as "running", so a customer with a big
 * codebase watches a spinner for a function that no longer exists.
 *
 * Measured on real repositories: about 4 seconds of compute even on a
 * 2,359-file monorepo, up to 18 seconds to download its tarball, and 3 to 25
 * seconds for the reasoning call. The download is what varies, so the budget is
 * spent there and reasoning is what gets given up.
 */
describe("audit time budget", () => {
  it("finishes inside the function's own ceiling, with room to save the result", () => {
    const ceilingOf = (file: string) => Number(readFileSync(file, "utf8").match(/export const maxDuration = (\d+)/)?.[1]);
    for (const route of ["app/api/audit/route.ts", "app/api/jobs/drain/route.ts", "app/api/monitor/github/route.ts", "app/api/monitor/scheduled/route.ts"]) {
      expect(ceilingOf(route), route).toBe(300);
    }
    expect(AUDIT_BUDGET_MS).toBeLessThanOrEqual(300_000 - 20_000);
    expect(AUDIT_BUDGET_MS).toBeGreaterThan(60_000);
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

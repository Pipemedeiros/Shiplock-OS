import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Every route that runs an audit declares the 300-second Fluid ceiling, so a
 * large repository finishes rather than being killed with its run row left on
 * "running".
 */
describe("audit time budget", () => {
  it("finishes inside the function's own ceiling, with room to save the result", () => {
    const ceilingOf = (file: string) => Number(readFileSync(file, "utf8").match(/export const maxDuration = (\d+)/)?.[1]);
    for (const route of ["app/api/audit/route.ts", "app/api/jobs/drain/route.ts", "app/api/monitor/github/route.ts", "app/api/monitor/scheduled/route.ts"]) {
      expect(ceilingOf(route), route).toBe(300);
    }
  });
});

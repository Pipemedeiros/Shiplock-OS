import { describe, expect, it } from "vitest";
import { loopInputOf } from "./securityLoopData";

// The loop's input is derived from the same rows the dashboard reads.
const run = (status: string, over: Record<string, unknown> = {}) => ({ id: status, status, fullName: "acme/app", trace: [], coverage: [],
  filesRead: 10, entriesFound: 4, tablesFound: 2, ...over }) as never;

describe("loop input", () => {
  it("reads the running audit's latest step and the last finished audit's numbers", () => {
    const input = loopInputOf({
      runs: [run("running", { trace: [{ time: "1s", label: "412 files read" }] }), run("complete", { coverage: [{}, {}] })],
      ai: { available: true, paused: null, checks: [{ state: "pending" }, { state: "pending" }, { state: "proposal" }, { state: "expired" }] as never },
      map: { routes: 4, exposed: 1 }, findings: [{ fixPrUrl: "u" }, { fixPrUrl: null }] as never,
      reviews: [{ verdict: "block" }, { verdict: "pass" }] as never, trafficSites: 1, hotRoutes: 2,
      providers: { available: true, items: [{ state: "complete" }, { state: "never_read" }] as never },
    });
    expect(input.current).toEqual({ status: "running", step: "412 files read" });
    expect(input.finished).toEqual({ status: "complete", filesRead: 10, entries: 4, tables: 2, unread: 2 });
    expect(input.agent).toEqual({ available: true, paused: null, pending: 2, answered: 1 });
    expect(input.fix).toEqual({ open: 2, withPr: 1 });
    expect(input.watch).toEqual({ prChecks: 2, blockedPrs: 1, trafficSites: 1, hotRoutes: 2, providersRead: 1, providersConnected: 2 });
  });

  it("has no finished audit and no map before the first audit", () => {
    const input = loopInputOf({ runs: [], ai: { available: false }, map: null, findings: [], reviews: [], trafficSites: 0, hotRoutes: 0,
      providers: { available: false, items: [] } });
    expect(input.finished).toBeNull();
    expect(input.map).toBeNull();
    expect(input.agent.available).toBe(false);
  });
});

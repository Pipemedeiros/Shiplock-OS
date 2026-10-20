import { describe, expect, it } from "vitest";
import { securityLoop, type LoopInput } from "./securityLoop";

// Felipe 2026-10-06: read, attack, map, fix, then watch with traffic and
// cross-layer context, and SHOW each one being done. Every stage states what
// actually happened; pending is never done, and nothing says secure.
const base: LoopInput = {
  current: null,
  finished: { status: "complete", filesRead: 412, entries: 38, tables: 9, unread: 2 },
  agent: { available: true, paused: null, pending: 0, answered: 0 },
  map: { routes: 38, exposed: 0 },
  fix: { open: 0, withPr: 0 },
  watch: { prChecks: 3, blockedPrs: 0, trafficSites: 0, hotRoutes: 0, hotWithIssue: 0, hotWithReview: 0, providersRead: 0, providersConnected: 0 },
};
const stage = (input: LoopInput, key: string) => securityLoop(input).find((s) => s.key === key)!;

describe("security loop", () => {
  it("runs in Felipe's order", () => {
    expect(securityLoop(base).map((s) => s.title)).toEqual(["Read", "Attack", "Map", "Fix", "Watch"]);
  });

  it("before any audit, offers the first one and leaves the rest waiting on it", () => {
    const loop = securityLoop({ ...base, finished: null, map: null });
    expect(loop[0]).toMatchObject({ state: "off", headline: "Not audited", action: "Run an audit" });
    for (const s of loop.slice(1)) expect(s.state).toBe("off");
  });

  it("shows an audit in progress as working, with its current step", () => {
    const s = stage({ ...base, current: { status: "running", step: "412 files read" } }, "read");
    expect(s).toMatchObject({ state: "working", headline: "Reading now" });
    expect(s.detail).toContain("412 files read");
  });

  it("says what the last audit read and what it did not", () => {
    const s = stage(base, "read");
    expect(s).toMatchObject({ state: "done", headline: "412 files read" });
    expect(s.detail).toContain("2 areas not checked");
  });

  it("flags a stopped audit", () => {
    expect(stage({ ...base, finished: { ...base.finished!, status: "failed" } }, "read").state).toBe("attention");
  });

  it("says attack reasoning has not run until the customer's agent is connected", () => {
    const s = stage({ ...base, agent: { available: true, paused: "not_connected", pending: 0, answered: 0 } }, "attack");
    expect(s).toMatchObject({ state: "off", headline: "Not run", action: "Connect your agent" });
    expect(s.detail).toMatch(/your own agent/);
  });

  it("shows tasks waiting on the agent as waiting, never as done", () => {
    const s = stage({ ...base, agent: { available: true, paused: null, pending: 3, answered: 1 } }, "attack");
    expect(s).toMatchObject({ state: "waiting", headline: "3 tasks wait for your agent" });
    expect(securityLoop({ ...base, agent: { ...base.agent, pending: 1 } })[1].headline).toBe("1 task waits for your agent");
  });

  it("counts answers the server checked against the code", () => {
    const s = stage({ ...base, agent: { available: true, paused: null, pending: 0, answered: 2 } }, "attack");
    expect(s).toMatchObject({ state: "done", headline: "2 answers checked" });
    expect(s.detail).toMatch(/quoted lines/);
  });

  it("does not guess when agent activity cannot be read", () => {
    expect(stage({ ...base, agent: { available: false, paused: null, pending: 0, answered: 0 } }, "attack").state).toBe("attention");
  });

  it("maps routes and calls out exposed ones", () => {
    expect(stage(base, "map")).toMatchObject({ state: "done", headline: "38 routes mapped" });
    expect(stage({ ...base, map: { routes: 38, exposed: 4 } }, "map")).toMatchObject({ state: "attention", detail: "4 exposed" });
  });

  it("offers fixes for open issues and counts opened pull requests", () => {
    const s = stage({ ...base, fix: { open: 5, withPr: 2 } }, "fix");
    expect(s).toMatchObject({ state: "attention", headline: "5 open issues", action: "View issues", href: "/dashboard/risks" });
    expect(s.detail).toContain("2 with a fix pull request");
  });

  it("says no open issues only about the code the audit read", () => {
    const s = stage(base, "fix");
    expect(s).toMatchObject({ state: "done", headline: "No open issues" });
    expect(s.detail).toMatch(/code the last audit read/);
  });

  it("watches pull requests and names the live context that is missing", () => {
    const s = stage(base, "watch");
    expect(s.state).toBe("done");
    expect(s.detail).toMatch(/3 pull requests checked/);
    expect(s.detail).toMatch(/no traffic/);
    expect(s.detail).toMatch(/no provider/);
  });

  it("adds traffic and provider context, and flags routes hit hard", () => {
    const s = stage({ ...base, watch: { ...base.watch, trafficSites: 1, hotRoutes: 2, providersRead: 1, providersConnected: 1 } }, "watch");
    expect(s).toMatchObject({ state: "attention", headline: "2 routes hit hard" });
    expect(s.detail).toMatch(/traffic from 1 site/);
    expect(s.detail).toMatch(/1 provider read live/);
  });

  it("watches with the attack's context: a route under attack that has an open issue leads (P4)", () => {
    const one = stage({ ...base, watch: { ...base.watch, trafficSites: 1, hotRoutes: 2, hotWithIssue: 1 } }, "watch");
    expect(one).toMatchObject({ state: "attention", headline: "1 route under attack has an open issue", action: "View issues", href: "/dashboard/risks" });
    const two = stage({ ...base, watch: { ...base.watch, trafficSites: 1, hotRoutes: 3, hotWithIssue: 2 } }, "watch");
    expect(two.headline).toBe("2 routes under attack have an open issue");
    const review = stage({ ...base, watch: { ...base.watch, trafficSites: 1, hotRoutes: 1, hotWithReview: 1 } }, "watch");
    expect(review).toMatchObject({ headline: "1 route under attack has a finding to review", action: "Review first" });
  });

  it("never says secure and never uses a dash", () => {
    const inputs: LoopInput[] = [base, { ...base, finished: null, map: null }, { ...base, fix: { open: 1, withPr: 0 } },
      { ...base, current: { status: "queued", step: null } }];
    for (const input of inputs) for (const s of securityLoop(input)) {
      expect(`${s.headline} ${s.detail} ${s.action ?? ""}`).not.toMatch(/\bsecure\b|\bsafe\b|[–—]| - /i);
    }
  });
});

import { describe, expect, it } from "vitest";
import { assessSurge, describeSurge, median, planResponse, shouldShed } from "./surge";

const w = (requests: number, sources: number, topPathRequests = Math.floor(requests * 0.2), topPath = "/api/search") =>
  ({ requests, sources, topPathRequests, topPath });

const calmBaseline = Array.from({ length: 8 }, () => w(200, 40, 40));

describe("median", () => {
  it("is robust to a previous spike", () => {
    expect(median([100, 100, 100, 100, 9000])).toBe(100);
  });
  it("handles even counts and empty input", () => {
    expect(median([10, 20])).toBe(15);
    expect(median([])).toBe(0);
  });
});

describe("assessSurge", () => {
  // A new customer's first busy hour is not an attack.
  it("refuses to judge without enough history", () => {
    const a = assessSurge(w(5000, 900, 4800), [w(200, 40)]);
    expect(a.surging).toBe(false);
    expect(a.reason).toContain("Not enough history");
  });

  it("refuses to judge when the app has almost no traffic", () => {
    const a = assessSurge(w(300, 200, 290), Array.from({ length: 8 }, () => w(5, 2, 1)));
    expect(a.surging).toBe(false);
    expect(a.reason).toContain("too low");
  });

  it("is quiet on normal variation", () => {
    expect(assessSurge(w(400, 60, 80), calmBaseline).surging).toBe(false);
  });

  // A launch brings many sources to many pages. That must not page anyone.
  it("does NOT call a broad traffic spike an attack", () => {
    const a = assessSurge(w(4000, 900, 400), calmBaseline);
    expect(a.surging).toBe(false);
    expect(a.reason).toContain("real attention rather than an attack");
  });

  it("calls a concentrated spike from many sources an attack", () => {
    const a = assessSurge(w(4000, 900, 3800), calmBaseline);
    expect(a.surging).toBe(true);
    expect(a.distributed).toBe(true);
    expect(a.multiple).toBeGreaterThan(5);
  });

  it("marks a concentrated spike from few sources as not distributed", () => {
    const a = assessSurge(w(4000, 6, 3800), calmBaseline);
    expect(a.surging).toBe(true);
    expect(a.distributed).toBe(false);
  });

  it("handles an empty window without dividing by zero", () => {
    expect(assessSurge(w(0, 0, 0), calmBaseline).surging).toBe(false);
  });
});

describe("what we tell them", () => {
  it("says nothing when there is no surge", () => {
    expect(describeSurge(w(400, 60, 80), assessSurge(w(400, 60, 80), calmBaseline))).toEqual([]);
  });

  // The distributed case is exactly where per-source blocking fails, and
  // pretending otherwise would be the dishonest version.
  it("admits that blocking individual addresses will not stop a distributed flood", () => {
    const current = w(4000, 900, 3800);
    const out = describeSurge(current, assessSurge(current, calmBaseline));
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain("blocking individual addresses will not stop it");
  });

  it("names the database rather than bandwidth as what is at risk", () => {
    const current = w(4000, 900, 3800);
    const out = describeSurge(current, assessSurge(current, calmBaseline));
    expect(out[0].consequence).toContain("runs out of connections");
  });

  it("reports the few-source case at WARNING and says it is already handled", () => {
    const current = w(4000, 6, 3800);
    const out = describeSurge(current, assessSurge(current, calmBaseline));
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("have been blocked");
  });
});

describe("load shedding", () => {
  // An app that stays up but cannot let anyone log in or pay has failed in the
  // way that costs money. Shedding those is how a defence becomes the outage.
  it("NEVER sheds auth, checkout or webhook paths", () => {
    for (const p of ["/api/auth/callback", "/login", "/signup", "/api/checkout", "/api/billing", "/api/webhook", "/api/stripe"]) {
      expect(shouldShed(p, true), p).toBe(false);
    }
  });

  it("sheds ordinary paths under surge", () => {
    expect(shouldShed("/api/search", true)).toBe(true);
    expect(shouldShed("/api/feed", true)).toBe(true);
  });

  it("sheds nothing when there is no surge", () => {
    expect(shouldShed("/api/search", false)).toBe(false);
  });
});

describe("the autonomous response", () => {
  it("does nothing when there is no surge", () => {
    const current = w(400, 60, 80);
    expect(planResponse(current, assessSurge(current, calmBaseline), calmBaseline).action).toBe("none");
  });

  // Tier 1 by the doctrine: reversible, bounded to one endpoint, self-lifting.
  it("throttles the targeted path to about 1.5x its OWN normal rate", () => {
    const current = w(4000, 900, 3800);
    const plan = planResponse(current, assessSurge(current, calmBaseline), calmBaseline);
    expect(plan.action).toBe("throttle_path");
    expect(plan.path).toBe("/api/search");
    expect(plan.allowancePerMinute).toBe(60); // baseline 40 * 1.5 -> floored at 60
    expect(plan.reversible).toBe(true);
  });

  it("scales the allowance with a busier app rather than using a fixed number", () => {
    const busy = Array.from({ length: 8 }, () => w(20000, 3000, 8000));
    const current = w(200000, 9000, 190000);
    const plan = planResponse(current, assessSurge(current, busy), busy);
    expect(plan.allowancePerMinute).toBe(12000);
  });

  it("explains that real users fit inside the budget and it lifts itself", () => {
    const current = w(4000, 900, 3800);
    const plan = planResponse(current, assessSurge(current, calmBaseline), calmBaseline);
    expect(plan.explanation).toContain("Your real users are inside that budget");
    expect(plan.explanation).toContain("Lifts automatically");
  });
});

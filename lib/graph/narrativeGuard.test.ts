import { describe, it, expect } from "vitest";
import { checkNarrative } from "./narrativeGuard";
import type { AttackPath } from "./attackPaths";

function path(over: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "path:anon_route_unprotected_table",
    severity: "CRITICAL",
    title: "Orders table readable across tenants",
    consequence: "…",
    evidence: [
      { collector: "source", fact: "/api/orders resolves no user identity" },
      { collector: "db", fact: "public.orders has no RLS policy" },
    ],
    score: 9,
    surfaces: ["source", "db"],
    ...over,
  };
}

describe("checkNarrative — grounding", () => {
  it("allows a narrative built only from supplied facts", () => {
    const verdict = checkNarrative(
      {
        narrative:
          "The route that serves your orders does not resolve a user, and the table behind it has no policy limiting who can read it. Either alone would be ordinary; together they mean anyone can read every tenant's orders.",
        citedFacts: [
          "/api/orders resolves no user identity",
          "public.orders has no RLS policy",
        ],
      },
      path()
    );
    expect(verdict.allowed).toBe(true);
  });

  // The prose equivalent of agentGuard's "every FROM target must be in the
  // replica schema": the model may reorganise what it was given, never add.
  it("rejects a narrative citing a fact that was never collected", () => {
    const verdict = checkNarrative(
      {
        narrative: "Your admin panel is also exposed.",
        citedFacts: ["/api/admin has no auth check"],
      },
      path()
    );
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.reason).toMatch(/never collected/);
  });

  it("rejects a narrative that cites nothing", () => {
    const verdict = checkNarrative(
      { narrative: "This looks bad and you should fix it.", citedFacts: [] },
      path()
    );
    expect(verdict.allowed).toBe(false);
  });

  it("rejects an empty narrative rather than showing a blank finding", () => {
    expect(checkNarrative({ narrative: "   ", citedFacts: ["x"] }, path()).allowed).toBe(false);
  });

  it("rejects a narrative longer than a summary", () => {
    const verdict = checkNarrative(
      {
        narrative: "x".repeat(701),
        citedFacts: ["public.orders has no RLS policy"],
      },
      path()
    );
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.reason).toMatch(/limit/);
  });
});

describe("checkNarrative — claims the evidence cannot license", () => {
  const cited = ["public.orders has no RLS policy"];

  it("rejects a claimed past breach — the graph observes reachability, never exfiltration", () => {
    const verdict = checkNarrative(
      { narrative: "Your customer records have been exfiltrated through this route.", citedFacts: cited },
      path()
    );
    expect(verdict.allowed).toBe(false);
  });

  it("rejects 'actively being exploited'", () => {
    expect(
      checkNarrative(
        { narrative: "This gap is actively being exploited right now.", citedFacts: cited },
        path()
      ).allowed
    ).toBe(false);
  });

  it("rejects a quantified impact claim — no collector counts affected records", () => {
    expect(
      checkNarrative(
        { narrative: "Roughly 4000 users affected by this exposure.", citedFacts: cited },
        path()
      ).allowed
    ).toBe(false);
  });

  it("rejects claiming customer data was accessed — ShipLock never reads it", () => {
    expect(
      checkNarrative(
        { narrative: "Your user data was accessed by an unauthorised party.", citedFacts: cited },
        path()
      ).allowed
    ).toBe(false);
  });

  it("still allows the honest present-tense framing of the same risk", () => {
    const verdict = checkNarrative(
      {
        narrative:
          "Anyone who finds this route can read rows belonging to other tenants, because nothing between the request and the table checks who is asking.",
        citedFacts: cited,
      },
      path()
    );
    expect(verdict.allowed).toBe(true);
  });
});

// Regression corpus. The first version of the unlicensed-claim list keyed on
// past-tense auxiliaries ("has been breached"), so every present-tense phrasing
// walked through a guard whose entire purpose was to stop those sentences. Both
// directions are asserted here, because a guard that over-blocks is its own
// failure: rejecting accurate wording only teaches the model to be vague.
describe("checkNarrative — compromise claims, any tense", () => {
  const cited = ["public.orders has no RLS policy"];
  const check = (narrative: string) =>
    checkNarrative({ narrative, citedFacts: cited }, path()).allowed;

  it.each([
    "Your database is breached right now.",
    "This table is compromised.",
    "Attackers are exfiltrating your orders table.",
    "Your customer data is being downloaded.",
    "Your records have been exfiltrated.",
    "Someone has already accessed your rows.",
    "The orders table was dumped last week.",
    "Hackers are reading your customer records.",
    "Your data is currently leaked.",
    "This is a confirmed breach.",
    "4000 users affected by this exposure.",
  ])("blocks: %s", (narrative) => {
    expect(check(narrative)).toBe(false);
  });

  it.each([
    "Anyone who finds this route can read rows belonging to other tenants, because nothing checks who is asking.",
    "Nothing between the request and the table checks who is asking.",
    // The single most valuable sentence the product writes, and bundleAudit
    // proves it by downloading the file. "exposed" is a state, not an event.
    "Your service-role key is exposed in the JavaScript your site ships to every visitor.",
    "Any caller could download every row in this table.",
    "Records can be read by anyone with the anon key.",
    "If someone found this endpoint they would be able to list other tenants' orders.",
    "The policy allows every authenticated user to select rows they do not own.",
    "This route resolves no user identity, and the table behind it has no policy.",
    // The product's own vocabulary for what is possible must stay sayable —
    // "exploitable" and "attack path" are not claims that anything happened.
    "This is exploitable by any unauthenticated caller.",
    "The attack path runs from the route straight through to the table.",
  ])("allows: %s", (narrative) => {
    expect(check(narrative)).toBe(true);
  });
});

describe("checkNarrative — traffic language is licensed by traffic evidence", () => {
  it("rejects traffic language when no traffic collector contributed", () => {
    const verdict = checkNarrative(
      {
        narrative: "We are seeing requests probing this route.",
        citedFacts: ["public.orders has no RLS policy"],
      },
      path()
    );
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.reason).toMatch(/traffic/);
  });

  // Regression: the first version of this rule matched the bare word "request"
  // and rejected ordinary prose describing a route. A guard that blocks honest
  // wording pushes the model toward vaguer wording to get past it, which is the
  // opposite of what it exists for.
  it("allows 'request' as an ordinary noun, without traffic evidence", () => {
    const verdict = checkNarrative(
      {
        narrative:
          "Nothing between the request and the table checks who is asking, so any caller reads every tenant's rows.",
        citedFacts: ["public.orders has no RLS policy"],
      },
      path()
    );
    expect(verdict.allowed).toBe(true);
  });

  it("allows traffic language when traffic actually contributed", () => {
    const withTraffic = path({
      evidence: [
        { collector: "source", fact: "/api/orders resolves no user identity" },
        { collector: "db", fact: "public.orders has no RLS policy" },
        { collector: "traffic", fact: "/api/orders is receiving flagged requests" },
      ],
      surfaces: ["source", "db", "traffic"],
    });

    const verdict = checkNarrative(
      {
        narrative:
          "This route is already receiving requests from sources we flagged, which is why it is ranked above the others.",
        citedFacts: ["/api/orders is receiving flagged requests"],
      },
      withTraffic
    );
    expect(verdict.allowed).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

// Voice and claim discipline on the customer-facing surfaces.
//
// PRODUCT-DESIGN §13: this reader is a competent engineer deciding whether to
// trust us with their company's data. What earns that is precision — naming the
// mechanism and the limit — not reassurance. These assertions exist because copy
// drifts toward persuasion under editing, and because a claim we cannot support
// is the same category of error as a finding we cannot demonstrate.

const read = (p: string) => readFileSync(p, "utf8");
const LANDING = read("app/(d)/page.tsx");
const COVERAGE = read("app/(d)/coverage/page.tsx");
const ACCESSIBILITY = read("app/(d)/accessibility/page.tsx");

describe("claims we must never make", () => {
  it("never claims DDoS protection — that is capacity we do not have", () => {
    for (const [name, src] of [["landing", LANDING], ["coverage", COVERAGE]] as const) {
      expect(src, name).not.toMatch(/\bDDoS protection\b|\bwe (stop|absorb|block) DDoS\b/i);
    }
  });

  // Must catch an AFFIRMATIVE claim without flagging the disclaimer that says
  // the opposite — "we do not attack your production application" is exactly the
  // sentence we want on the page.
  it("never claims we attack the customer's own application", () => {
    const affirmative = /(?<!not )(?<!never )attack (your|the customer's) (app|application|production|database)\b/i;
    expect(COVERAGE).not.toMatch(affirmative);
    expect(LANDING).not.toMatch(affirmative);
  });

  it("does say plainly that we do NOT attack production", () => {
    expect(COVERAGE).toMatch(/do not attack your production application/i);
  });

  it("never promises to guarantee security or prevent breaches", () => {
    for (const src of [LANDING, COVERAGE]) {
      expect(src).not.toMatch(/guarantee[sd]? (your )?(security|safety)|prevent(s)? (all )?breach/i);
    }
  });

  it("does not use urgency or scarcity to persuade", () => {
    for (const src of [LANDING, COVERAGE]) {
      expect(src).not.toMatch(/act now|limited time|don't wait|before it's too late|hurry/i);
    }
  });
});

describe("the sandboxed exploitation section", () => {
  it("states that the copy holds no customer data", () => {
    expect(LANDING).toMatch(/none of your data/i);
  });

  // A broken sandbox reporting "no leak" is the failure worth naming publicly.
  it("explains the control check rather than only the attack", () => {
    expect(LANDING).toMatch(/control query runs first/i);
    expect(LANDING).toMatch(/discarded rather than reported as clean/i);
  });

  it("says the agent proposes but does not decide", () => {
    expect(LANDING).toMatch(/contributes ideas, never authority/i);
    expect(LANDING).toMatch(/deterministic guard/i);
  });
});

describe("scope page", () => {
  it("states a boundary for every area it claims", () => {
    const areas = (COVERAGE.match(/name: "/g) ?? []).length;
    const limits = (COVERAGE.match(/limit:/g) ?? []).length;
    expect(areas).toBeGreaterThan(0);
    expect(limits).toBe(areas);
  });

  it("covers the four areas by name", () => {
    for (const area of ["Continuous review", "Sandboxed exploitation", "Traffic defence", "Verified remediation"]) {
      expect(COVERAGE).toContain(area);
    }
  });

  // Cancellation terms belong where someone evaluating the product will read
  // them, not only in the legal page.
  it("states the cancellation terms plainly", () => {
    expect(COVERAGE).toMatch(/self-serve/i);
    expect(COVERAGE).toMatch(/no cancellation fee/i);
    expect(COVERAGE).toMatch(/no early-termination fee/i);
  });

  it("says autonomous action is off by default", () => {
    expect(COVERAGE).toMatch(/off by default/i);
  });
});

describe("accessibility statement", () => {
  it("names the standard and level", () => {
    expect(ACCESSIBILITY).toMatch(/WCAG 2\.2/);
    expect(ACCESSIBILITY).toMatch(/Level AA/);
  });

  it("references the legal frameworks that cite it", () => {
    expect(ACCESSIBILITY).toMatch(/Americans with Disabilities Act/);
    expect(ACCESSIBILITY).toMatch(/Section 508/);
  });

  // Asserting untested conformance is the same error as an undemonstrated finding.
  it("states known limitations rather than claiming full conformance", () => {
    expect(ACCESSIBILITY).toMatch(/Known limitations/);
    expect(ACCESSIBILITY).toMatch(/rather than from verified user testing/i);
  });

  it("gives a reporting route and a response time", () => {
    expect(ACCESSIBILITY).toMatch(/support@shiplock\.dev/);
    expect(ACCESSIBILITY).toMatch(/two business days/i);
  });
});

describe("the exploitation animation", () => {
  const ANIM = read("components/d/ProvingAnimation.tsx");

  it("is readable as a diagram when motion is disabled", () => {
    expect(read("app/(d)/design-d.css")).toMatch(/prefers-reduced-motion[\s\S]{0,200}dxd-proving-stage \{ animation: none/);
  });

  it("describes the sequence to assistive technology", () => {
    expect(ANIM).toMatch(/role="img"/);
    expect(ANIM).toMatch(/aria-label=/);
  });

  it("costs no client JavaScript", () => {
    expect(ANIM).not.toMatch(/"use client"|useState|useEffect/);
  });
});

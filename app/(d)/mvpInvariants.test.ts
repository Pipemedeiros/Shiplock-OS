import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

/**
 * What the MVP promised to be.
 *
 * These are the decisions the product was rebuilt around. Each is easy to undo
 * accidentally during a copy edit or a merge, and each would change what the
 * product IS rather than how it reads.
 */

/**
 * Source with comments stripped.
 *
 * Every assertion here is a negative one, and the first run of this file failed
 * three times on its own subject matter: a comment explaining that we never ask
 * for a database password contains the words "database password". A guard that
 * fires on the sentence saying the opposite is a guard that gets deleted.
 */
const read = (p: string) =>
  readFileSync(p, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
const LANDING = read("app/(d)/page.tsx");
const ONBOARDING = read("components/v3/OnboardingFlow.tsx");
const ACCESS = read("lib/access.ts");

describe("the landing page while the MVP is open", () => {
  it("shows no price and no plan", () => {
    // Pricing returns with billing. Until then a number on this page is a
    // promise the product does not keep.
    expect(LANDING).not.toMatch(/\$\d|\/mo\b|per month|pricing/i);
  });

  it("sends every call to action to the same place", () => {
    // One decision on the page. A landing with three destinations is a landing
    // where nobody makes one.
    const hrefs = [...LANDING.matchAll(/href="(\/[a-z/-]*)"/g)].map((m) => m[1]);
    const ctas = hrefs.filter((h) => h === "/onboarding" || h === "/auth" || h === "/checkout");
    expect(new Set(ctas)).toEqual(new Set(["/onboarding", "/auth"]));
  });

  it("never claims a free trial or a card, because there is neither", () => {
    expect(LANDING).not.toMatch(/free trial|no credit card required|start your trial/i);
  });

  it("avoids the register that reads as marketing rather than engineering", () => {
    expect(LANDING).not.toMatch(
      /peace of mind|sleep at night|effortless|worry-free|bulletproof|unhackable|game.chang|supercharge|unlock the power|revolutionar/i,
    );
  });

  it("does not offer fixes the customer has to copy and paste", () => {
    // The product opens a pull request. "Here is a snippet, go apply it" is the
    // thing it was built to replace — so an affirmative offer is the failure,
    // not the sentence promising there is nothing to paste.
    expect(LANDING).not.toMatch(/copy the fix|paste (this|the) (fix|snippet|prompt)|copy this into/i);
  });
});

describe("onboarding asks for one connection", () => {
  it("never asks for a database credential", () => {
    // An input field, not a mention. The screen says out loud that it does not
    // want these, which is the point.
    const inputs = [...ONBOARDING.matchAll(/<input[^>]*>/g)].map((m) => m[0]).join(" ");
    expect(inputs).not.toMatch(/password|connection|dsn|key|token|secret/i);
    expect(ONBOARDING).not.toMatch(/postgres:\/\//);
  });

  it("only sends the customer to GitHub", () => {
    expect(ONBOARDING).toContain("/api/deep/github/connect");
    expect(ONBOARDING).not.toMatch(/api\/deep\/(supabase|postgres|vercel)/);
  });

  it("states that we never push to the default branch", () => {
    expect(ONBOARDING).toMatch(/never push to your default branch/i);
  });
});

describe("billing is parked, not half-removed", () => {
  it("keeps one switch for the whole paywall", () => {
    expect(ACCESS).toMatch(/BILLING_ENABLED = false/);
    expect(ACCESS).toMatch(/EMAIL_ALERTS_ENABLED = false/);
  });

  it("still refuses an account the database does not know", () => {
    // Parked billing must not become "anyone on the internet can have an audit
    // of a private repository".
    expect(ACCESS).toMatch(/if \(!profile\) return false/);
  });
});

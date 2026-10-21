import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Q30: settings is a full account page: plan and billing (manage, cancel),
// sign out, and a stated path to deleting the account.
const page = readFileSync("app/(d)/dashboard/settings/page.tsx", "utf8");

describe("settings account sections", () => {
  it("reads the caller's own Stripe customer to decide whether billing actions show", () => {
    expect(page).toMatch(/stripe_customer_id/);
    expect(page).toMatch(/<BillingActions \/>/);
  });

  it("has sign out and a delete account path that matches the privacy page", () => {
    expect(page).toMatch(/<SignOutButton \/>/);
    expect(page).toMatch(/mailto:support@shiplock\.dev\?subject=Delete%20my%20account/);
    expect(readFileSync("app/(d)/privacy/page.tsx", "utf8")).toMatch(/support@shiplock\.dev/);
  });

  it("offers two-step sign-in with an authenticator app", () => {
    expect(page).toMatch(/<TwoStepCard \/>/);
    expect(page).toMatch(/Two-step sign-in/);
  });

  it("keeps dashes out of its copy", () => {
    const copy = page.replace(/\{\/\*[\s\S]*?\*\/\}|\/\/[^\n]*/g, "");
    expect(copy).not.toMatch(/[–—]/);
  });

  // Design pass 2026-10-20: ten cards in one column, grouped by what the
  // founder is doing, in the order onboarding introduces them.
  it("groups its cards into five sections the jump list links to, in order", () => {
    const groups = [...page.matchAll(/<section id="([a-z]+)"/g)].map((m) => m[1]);
    expect(groups).toEqual(["connections", "ai", "security", "sharing", "account"]);
    for (const id of groups) expect(page).toContain(`href="#${id}"`);
    const order = ["GitHub", "Your app", "Database", "Traffic", "Your AI", "Agent pull requests", "Two-step sign-in", "Shared report", "Plan and billing", "Account<"];
    const at = order.map((title) => page.indexOf(`className="v3-eyebrow">${title}`));
    expect(at.every((i) => i > 0)).toBe(true);
    expect(at).toEqual([...at].sort((a, b) => a - b));
  });
});

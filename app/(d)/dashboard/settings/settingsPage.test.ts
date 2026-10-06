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
});

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

// Drift guard for the public preview.
//
// Twice in two days a customer-facing surface described a product that had
// changed underneath it: the traffic panel still said "Install protection" after
// detection stopped needing an install, and "Product preview" pointed at a
// dashboard design that had not existed since the page was split into four
// surfaces. Both were invisible to the test suite, because nothing asserts that
// a preview resembles the thing it previews.
//
// This is the cheap version of that assertion: every panel the real dashboard
// renders must also appear in the demo. It cannot check that the demo LOOKS
// right, but it does catch the failure that actually happened — a component
// added to or removed from the product while the preview kept rendering the old
// set.
//
// Deliberately structural rather than visual. A snapshot of markup would break
// on every copy edit and get regenerated without being read, which is how a
// guard becomes noise and then gets deleted.

const REAL_PAGES = [
  "app/(d)/dashboard/page.tsx",
  "app/(d)/dashboard/findings/page.tsx",
  "app/(d)/dashboard/watch/page.tsx",
  "app/(d)/dashboard/settings/page.tsx",
];
const DEMO = "app/(d)/dashboard-demo/page.tsx";

/**
 * Components the real dashboard imports from components/d that the demo is NOT
 * expected to render, each with the reason. Anything not listed here must
 * appear in the demo.
 */
const EXEMPT: Record<string, string> = {
  ManageBillingButton: "opens a real Stripe portal session for a signed-in customer",
  SignOutButton: "there is no session to end in a public preview",
  UpgradeButton: "starts a real checkout",
  ConnectAndScanForm: "runs a real scan against a real project",
  SupabasePanel: "starts a real OAuth flow",
};

function componentImports(file: string): string[] {
  const src = readFileSync(file, "utf8");
  const names = new Set<string>();
  // import { A, B as C } from "@/components/d/X"
  for (const m of src.matchAll(/import\s*\{([^}]+)\}\s*from\s*["']@\/components\/d\/[^"']+["']/g)) {
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      // Skip type-only imports — they render nothing.
      if (!name || name.startsWith("type ")) continue;
      names.add(name);
    }
  }
  return [...names];
}

describe("the preview must resemble the product it previews", () => {
  const demoImports = new Set(componentImports(DEMO));

  it("renders every panel the real dashboard renders", () => {
    const missing: string[] = [];
    for (const page of REAL_PAGES) {
      for (const name of componentImports(page)) {
        if (EXEMPT[name]) continue;
        if (!demoImports.has(name)) missing.push(`${name} (from ${page})`);
      }
    }
    expect(missing, `Preview is missing panels the real dashboard renders:\n  ${missing.join("\n  ")}`).toEqual([]);
  });

  // The specific regression: the demo kept rendering the old hero after the real
  // Overview moved to PostureHeadline.
  it("uses the same headline component as the real Overview", () => {
    expect(componentImports("app/(d)/dashboard/page.tsx")).toContain("PostureHeadline");
    expect(demoImports.has("PostureHeadline")).toBe(true);
  });

  it("uses the same board component as the real Findings tab", () => {
    expect(componentImports("app/(d)/dashboard/findings/page.tsx")).toContain("FindingsBoard");
    expect(demoImports.has("FindingsBoard")).toBe(true);
  });

  it("shows the section navigation, so the four-surface structure is visible", () => {
    expect(demoImports.has("DashboardTabs")).toBe(true);
  });

  // A preview that sends a logged-out visitor to a login wall is not a preview.
  it("renders the tab bar in inert demo mode", () => {
    expect(readFileSync(DEMO, "utf8")).toMatch(/<DashboardTabs[^>]*\bdemo\b/);
  });

  it("is marked as mock data and kept out of search results", () => {
    const src = readFileSync(DEMO, "utf8");
    expect(src).toMatch(/mock data/i);
    expect(src).toMatch(/robots:\s*\{\s*index:\s*false/);
  });

  // The stale URL was linked from the landing page for days.
  it("keeps /dashboard-preview working rather than 404ing a shared link", () => {
    const src = readFileSync("app/dashboard-preview/page.tsx", "utf8");
    expect(src).toContain("redirect");
    expect(src).toContain("/dashboard-demo");
  });

  it("has no customer-facing link left pointing at the retired preview path", () => {
    const landing = readFileSync("app/(d)/page.tsx", "utf8");
    expect(landing).not.toContain('href="/dashboard-preview"');
  });
});

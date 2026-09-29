import { describe, expect, it } from "vitest";
import robots from "./robots";

// Felipe (2026-09-29): a real robots.txt. Public marketing pages are indexed;
// signed-in areas, the API and private share links are not.
describe("robots.txt", () => {
  const rules = robots().rules as { userAgent: string; allow: string; disallow: string[] };

  it("keeps crawlers out of private and signed-in surfaces", () => {
    for (const path of ["/dashboard", "/onboarding", "/auth", "/api/", "/verified/"]) {
      expect(rules.disallow).toContain(path);
    }
  });

  it("allows the public site and names the sitemap", () => {
    expect(rules.userAgent).toBe("*");
    expect(rules.allow).toBe("/");
    expect(robots().sitemap).toMatch(/\/sitemap\.xml$/);
  });

  it("lists no route that no longer exists", () => {
    expect(rules.disallow).not.toContain("/dashboard-preview");
  });
});

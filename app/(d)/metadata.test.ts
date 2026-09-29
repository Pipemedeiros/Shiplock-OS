import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Felipe (2026-09-29): every page has a real title, copy has no dashes, and the
// footer carries a copyright year.
const src = (path: string) => readFileSync(path, "utf8");

describe("page titles and metadata", () => {
  it("gives every dashboard page its own title", () => {
    for (const page of ["dashboard", "dashboard/risks", "dashboard/activity", "dashboard/coverage", "dashboard/settings",
      "dashboard/prs", "dashboard/stack", "onboarding"]) {
      expect(src(`app/(d)/${page}/page.tsx`), page).toMatch(/export const metadata[\s\S]*?title:\s*"[^"]+"/);
    }
  });

  it("keeps dashes out of the site title and description", () => {
    const root = src("app/layout.tsx");
    const title = root.match(/title:\s*"([^"]+)"/)?.[1] ?? "";
    const description = root.match(/description:\s*\n?\s*"([^"]+)"/)?.[1] ?? "";
    expect(title).not.toMatch(/[–—]/);
    expect(description).not.toMatch(/[–—]/);
  });

  it("shows a copyright line with the current year in the landing footer", () => {
    expect(src("app/(d)/page.tsx")).toMatch(/©\s*\{new Date\(\)\.getFullYear\(\)\}\s*ShipLock/);
  });
});

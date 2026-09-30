import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// Felipe (2026-09-30): the dashboard felt slow and a click sometimes needed a
// second one. Causes: no loading boundary (a click changed nothing until the
// next page fully rendered, and dynamic routes could not be prefetched), and
// the session gate ran its two network reads in both the layout and the page.
vi.mock("next/navigation", () => ({ usePathname: () => "/dashboard" }));

describe("dashboard navigation", () => {
  it("has an instant, accessible loading state", async () => {
    const { default: Loading } = await import("./loading");
    const html = renderToStaticMarkup(<Loading />);
    expect(html).toContain('aria-busy="true"');
    expect(html).toMatch(/role="status"/);
    expect(html).toContain("Loading");
  });

  it("marks the clicked tab while it loads", () => {
    const nav = readFileSync("components/v3/DashboardNav.tsx", "utf8");
    expect(nav).toMatch(/useLinkStatus/);
  });

  it("runs the session gate once per request, shared by layout and page", () => {
    expect(readFileSync("lib/dashboard.ts", "utf8")).toMatch(/export const requireDashboardSession = cache\(/);
  });
});

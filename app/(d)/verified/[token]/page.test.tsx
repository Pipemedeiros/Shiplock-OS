import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { VerifiedReport } from "@/lib/verified/report";

const getVerifiedReport = vi.fn();
vi.mock("@/lib/verified/report", () => ({ getVerifiedReport: (t: string) => getVerifiedReport(t) }));

const { default: VerifiedReportPage } = await import("./page");
const render = async () => renderToStaticMarkup(await VerifiedReportPage({ params: Promise.resolve({ token: "t" }) }));

const report: VerifiedReport = {
  status: "assessed", repository: "acme/app", commit: "abc1234", assessedAt: "2026-10-18T12:00:00Z", ageDays: 2,
  stale: false, trigger: "push", read: { files: 212, entries: 40, tables: 9 },
  assessment: { known: true, dataTouching: 20, assessed: 14, unassessed: 6, unassessedShare: 30,
    reasons: { identity: 4, scope: 2, signature: 0 }, dataUnreadable: 0 },
  openCritical: 1, openTotal: 5,
  notCovered: ["Runtime configuration."], live: ["The live site was read on October 18, 2026."],
  headline: "1 unresolved critical issue on the part of acme/app that was assessed.", disclaimer: "Not a certification.",
};

// The shareable report is read by a reviewer outside the company; it wears
// the v3 design (navy, porcelain, hairlines) and states its gaps before its result.
describe("Verified report page", () => {
  beforeEach(() => getVerifiedReport.mockReset());

  it("renders in the v3 shell with the headline in the serif and the gaps before the findings", async () => {
    getVerifiedReport.mockResolvedValue(report);
    const html = await render();
    expect(html).toMatch(/^<main class="v3 v3-vr"/);
    expect(html).not.toContain("dxd");
    expect(html).toMatch(/<h1 class="v3-serif[^"]*">1 unresolved critical issue/);
    expect(html.indexOf("Could not be assessed")).toBeGreaterThan(-1);
    expect(html.indexOf("Could not be assessed")).toBeLessThan(html.indexOf("Unresolved critical"));
    expect(html).toContain("not reported as safe");
    expect(html).toContain("The live site was read on October 18, 2026.");
    expect(html).toContain("Runtime configuration.");
    expect(html).toContain("acme/app · commit abc1234 · assessed October 18, 2026 (2 days ago)");
  });

  it("puts a critical count in the crit tone and a large unassessed share in warn, never crit", async () => {
    getVerifiedReport.mockResolvedValue(report);
    const html = await render();
    expect(html).toMatch(/v3-metric tone-crit"><span class="v3-metric-value">1</);
    expect(html).toMatch(/v3-metric tone-warn"><span class="v3-metric-value">6 \(30%\)</);
  });

  it("says nothing was assessed when no audit completed", async () => {
    getVerifiedReport.mockResolvedValue({ ...report, status: "never_assessed", assessment: null, live: null, headline: "Not assessed yet." });
    const html = await render();
    expect(html).toContain("no audit has completed");
    expect(html).not.toContain("Unresolved critical");
  });

  it("shows the same page for a disabled report and an unknown token", async () => {
    getVerifiedReport.mockResolvedValue(null);
    const html = await render();
    expect(html).toMatch(/^<main class="v3 v3-vr"/);
    expect(html).toContain("There is no active ShipLock report at this link.");
  });
});

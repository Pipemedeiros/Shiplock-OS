import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// Q30 (Felipe 2026-09-29): an onboarding-complete thank-you page and a kind
// page after a cancellation. Plain words, no dashes, a clear way forward.
vi.mock("@/lib/dashboard", () => ({ requireDashboardSession: async () => ({ userId: "u" }) }));
const text = (html: string) => html.replace(/<[^>]+>/g, " ");

describe("welcome and cancelled pages", () => {
  it("welcome thanks the founder and points at the next three things", async () => {
    const { default: Welcome, metadata } = await import("./welcome/page");
    const html = renderToStaticMarkup(await Welcome());
    expect(metadata.title).toBe("You are set up");
    expect(html).toMatch(/Thank you/);
    for (const href of ["/dashboard", "/dashboard/risks", "/dashboard/settings"]) expect(html).toContain(`href="${href}"`);
    expect(text(html)).not.toMatch(/[–—]/);
  });

  it("cancelled says what happens next, asks what fell short, and is not indexed", async () => {
    const { default: Cancelled, metadata } = await import("./cancelled/page");
    const html = renderToStaticMarkup(Cancelled());
    expect(metadata.robots).toEqual({ index: false, follow: false });
    expect(html).toMatch(/sorry/i);
    expect(html).toContain("mailto:support@shiplock.dev");
    expect(html).toContain('href="/dashboard"');
    expect(text(html)).not.toMatch(/[–—]/);
  });

  it("onboarding ends on the welcome page", () => {
    expect(readFileSync("components/v3/OnboardingFlow.tsx", "utf8")).toMatch(/onDone=\{\(\) => router\.push\("\/welcome"\)\}/);
  });
});

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ProviderCoverage } from "./ProviderCoverage";
import type { ProviderCoverageItem } from "@/lib/monitoring/providerCoverage";

const item = (over: Partial<ProviderCoverageItem>): ProviderCoverageItem => ({ transport: "supabase-management",
  label: "Supabase project", state: "complete", observedAt: "2026-09-22T10:00:00.000Z", notRead: [], detail: "Everything was read.", ...over });

describe("ProviderCoverage", () => {
  it("says no provider is connected rather than showing nothing", () => {
    const html = renderToStaticMarkup(<ProviderCoverage coverage={{ available: true, items: [] }} />);
    expect(html).toMatch(/No provider is connected/);
  });
  it("says so when snapshot history could not be loaded", () => {
    expect(renderToStaticMarkup(<ProviderCoverage coverage={{ available: false, items: [] }} />)).toMatch(/could not load/i);
  });
  it("renders each state with its time and what was not read", () => {
    const html = renderToStaticMarkup(<ProviderCoverage coverage={{ available: true, items: [
      item({}), item({ transport: "vercel", label: "Vercel", state: "partial", notRead: ["Vercel project marketing-site"], detail: "Part of it could not be read." }),
      item({ transport: "postgres-direct", label: "Postgres database", state: "failed", detail: "The last read failed." }),
      item({ transport: "app-surface", label: "Live app", state: "never_read", observedAt: null, detail: "Not read yet." }),
    ] }} />);
    expect(html).toContain("Read completely");
    expect(html).toContain("Partly read");
    expect(html).toContain("Vercel project marketing-site");
    expect(html).toContain("Last read failed");
    expect(html).toContain("Not read yet");
    expect(html).toContain("2026-09-22 10:00 UTC");
    expect(html).not.toMatch(/clean|passed/i);
  });
});

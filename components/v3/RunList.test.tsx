import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RunList } from "./RunList";
import type { DashboardRun } from "@/lib/agent/dashboardData";

// Felipe 2026-10-06: an audit in progress reads as in progress, never as a
// finished run that read nothing.
const run = (over: Partial<DashboardRun>): DashboardRun => ({
  id: "r1", fullName: "acme/app", status: "complete", trigger: "manual", startedAt: "2026-10-06T00:00:00Z",
  finishedAt: null, findingsCount: 0, entriesFound: null, tablesFound: null, filesRead: null, trace: [],
  coverage: [], error: null, stack: null, domain: null, routeFacts: null, ...over,
} as DashboardRun);

describe("run list", () => {
  it("shows a running audit's current step, not zero files read", () => {
    const html = renderToStaticMarkup(<RunList runs={[run({ status: "running", trace: [{ time: "2s", label: "412 files read" }] })]} />);
    expect(html).toContain("running");
    expect(html).toContain("Step 1. 412 files read");
    expect(html).not.toContain("0 files");
  });
  it("says a queued audit is waiting", () => {
    const html = renderToStaticMarkup(<RunList runs={[run({ status: "queued" })]} />);
    expect(html).toContain("Waiting for a worker");
    expect(html).not.toContain("0 files");
  });
  it("keeps the summary for a finished audit", () => {
    expect(renderToStaticMarkup(<RunList runs={[run({ filesRead: 12, entriesFound: 3, tablesFound: 2, findingsCount: 1 })]} />))
      .toContain("12 files · 3 entries · 2 tables · 1 finding");
  });
});

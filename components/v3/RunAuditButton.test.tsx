import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => {} }) }));
import { AuditProgressLine } from "./RunAuditButton";

// Felipe 2026-10-06: the customer has to see the audit working. While it
// runs, the button says which step it is on, as one status message.
const render = (run: Parameters<typeof AuditProgressLine>[0]["run"]) => renderToStaticMarkup(<AuditProgressLine run={run} />);

describe("audit progress line", () => {
  it("says a queued audit is waiting, not running", () => {
    const html = render({ status: "queued", trace: [], findings_count: 0, entries_found: null });
    expect(html).toContain("Queued");
    expect(html).toMatch(/role="status"/);
  });

  it("names the step the audit is on and how many have run", () => {
    const html = render({ status: "running", findings_count: 0, entries_found: null, trace: [
      { time: "0s", label: "Read-only checkout of acme/app" },
      { time: "2s", label: "412 files read", note: "3,200 KB of source" },
      { time: "3s", label: "Stack read from the code" },
    ] });
    expect(html).toContain("Stack read from the code");
    expect(html).toContain("Step 3");
    expect(html).toMatch(/aria-atomic="true"/);
  });

  it("says what was found as it is found", () => {
    const html = render({ status: "running", findings_count: 0, entries_found: null, trace: [
      { time: "4s", label: "2 committed credential or configuration-exposure issues", found: true },
    ] });
    expect(html).toContain("2 committed credential");
  });

  it("shows nothing before the first answer, and uses no dashes", () => {
    expect(render(null)).toBe("");
    const html = render({ status: "running", trace: [], findings_count: 0, entries_found: null });
    expect(html).toContain("Starting");
    expect(html).not.toMatch(/[–—]/);
  });
});

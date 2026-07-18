import { describe, expect, it } from "vitest";
import { buildBadgeSnippet, reportUrl } from "./badge";

describe("buildBadgeSnippet", () => {
  it("links to the live report and is self-contained", () => {
    const html = buildBadgeSnippet("tok-123", "https://shiplock.dev");
    expect(html).toContain('href="https://shiplock.dev/verified/tok-123"');
    expect(html).toContain("Secured by ShipLock");
    expect(html).toContain("<svg"); // inline mark, not a hotlinked image
    expect(html).not.toContain("<img");
    expect(html).toContain('rel="noopener noreferrer"');
  });

  it("normalizes a trailing slash in the app URL", () => {
    expect(reportUrl("t", "https://shiplock.dev/")).toBe("https://shiplock.dev/verified/t");
  });
});

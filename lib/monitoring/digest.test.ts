import { describe, it, expect } from "vitest";
import { buildDigestText, type DigestData } from "./digest";

const base: DigestData = {
  passes: 84,
  newFindings: 0,
  resolvedFindings: 0,
  openFindings: 0,
  openCritical: 0,
  requestsWatched: 12_400,
  threatsHandled: 0,
  worthSending: true,
};

const APP = "https://shiplock.dev";

describe("buildDigestText", () => {
  it("leads with reassurance when nothing is open", () => {
    expect(buildDigestText(base, APP)).toContain("Nothing new, and nothing open.");
  });

  it("leads with the critical count when one is open", () => {
    const t = buildDigestText({ ...base, openCritical: 2, openFindings: 3 }, APP);
    expect(t).toContain("2 critical issues still open.");
  });

  // The whole point of the digest: a quiet week must still look like work.
  it("reports the work done even when nothing was found", () => {
    const t = buildDigestText(base, APP);
    expect(t).toContain("84 monitoring passes");
    expect(t).toContain("12,400 requests checked");
    expect(t).toMatch(/That's the product working, not a gap in it/);
  });

  // traffic_events is pruned at 48h, so a weekly digest must not imply the
  // request count covers seven days.
  it("labels request volume with its real 48h window, not the digest period", () => {
    expect(buildDigestText(base, APP)).toContain("last 48h");
  });

  it("omits lines for things that didn't happen rather than printing zeroes", () => {
    const t = buildDigestText(base, APP);
    expect(t).not.toContain("0 finding");
    expect(t).not.toContain("0 source");
  });

  it("does not claim silence when findings were alerted", () => {
    const t = buildDigestText({ ...base, newFindings: 3 }, APP);
    expect(t).toContain("3 new findings");
    expect(t).toContain("alerted separately");
    expect(t).not.toMatch(/didn't email you this week/);
  });

  it("never carries fix content — titles and counts only", () => {
    const t = buildDigestText({ ...base, newFindings: 2, openFindings: 2 }, APP);
    expect(t).not.toMatch(/ALTER TABLE|CREATE POLICY|codefix/i);
  });

  it("links to the dashboard and offers an opt-out", () => {
    const t = buildDigestText(base, APP);
    expect(t).toContain("https://shiplock.dev/dashboard");
    expect(t).toContain("turn them off");
  });

  it("singularises counts of one", () => {
    const t = buildDigestText({ ...base, passes: 1, resolvedFindings: 1 }, APP);
    expect(t).toContain("1 monitoring pass run");
    expect(t).toContain("1 finding resolved");
  });
});

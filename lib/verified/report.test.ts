import { describe, expect, it } from "vitest";
import { buildVerifiedReport, type VerifiedReportData } from "./report";

const NOW = Date.parse("2026-07-17T12:00:00Z");
const base: VerifiedReportData = {
  isPaid: true,
  enabled: true,
  monitoringEnabled: true,
  lastScanAt: "2026-07-17T09:00:00Z", // 3h ago — recent
  projectHashSuffix: "abc123",
  openCriticalCount: 0,
  openIssueCount: 0,
  issuesResolved: 4,
  trafficInstalled: true,
  sessionSigning: "asymmetric",
  nowMs: NOW,
};

describe("buildVerifiedReport — status logic", () => {
  it("is verified when paid + enabled + monitoring + recent scan", () => {
    expect(buildVerifiedReport(base).status).toBe("verified");
  });
  it("degrades to inactive when the subscription lapsed", () => {
    expect(buildVerifiedReport({ ...base, isPaid: false }).status).toBe("inactive");
  });
  it("is inactive when the owner hasn't enabled sharing", () => {
    expect(buildVerifiedReport({ ...base, enabled: false }).status).toBe("inactive");
  });
  it("is inactive when the last scan is stale (> 72h)", () => {
    expect(buildVerifiedReport({ ...base, lastScanAt: "2026-07-10T09:00:00Z" }).status).toBe("inactive");
  });
  it("is inactive when there is no scan at all", () => {
    expect(buildVerifiedReport({ ...base, lastScanAt: null }).status).toBe("inactive");
  });
});

describe("buildVerifiedReport — posture math", () => {
  it("computes checksPassing from open issues, floored at 0", () => {
    expect(buildVerifiedReport({ ...base, openIssueCount: 3 }).checksPassing).toBe(13);
    expect(buildVerifiedReport({ ...base, openIssueCount: 99 }).checksPassing).toBe(0);
  });
  it("reports clean only when there are no open criticals", () => {
    expect(buildVerifiedReport(base).clean).toBe(true);
    expect(buildVerifiedReport({ ...base, openCriticalCount: 2 }).clean).toBe(false);
  });
  it("never reports negative resolved counts", () => {
    expect(buildVerifiedReport({ ...base, issuesResolved: -5 }).issuesResolved).toBe(0);
  });
});

describe("buildVerifiedReport — attacker-safe / paywall-safe projection", () => {
  it("carries no fix/codefix/url/key/finding-title fields, even with criticals open", () => {
    const report = buildVerifiedReport({ ...base, openCriticalCount: 3, openIssueCount: 5 });
    const json = JSON.stringify(report).toLowerCase();
    for (const forbidden of ["codefix", "\"fix\"", "anon", "service_role", "eyj", "http://", "https://", "supabase.co", "title"]) {
      expect(json).not.toContain(forbidden);
    }
  });
  it("never uses guarantee language in the disclaimer", () => {
    const d = buildVerifiedReport(base).disclaimer.toLowerCase();
    expect(d).toContain("not a guarantee");
    for (const banned of ["certified secure", "unhackable", "100%", "fully secure"]) {
      expect(d).not.toContain(banned);
    }
  });
});

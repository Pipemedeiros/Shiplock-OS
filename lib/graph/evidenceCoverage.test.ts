import { beforeEach, describe, expect, it, vi } from "vitest";
import { getEvidenceCoverage, summarizeEvidence } from "./evidenceCoverage";

const { eq, select } = vi.hoisted(() => ({ eq: vi.fn(), select: vi.fn() }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: () => ({ select }) }),
}));
const recordedAt = "2026-09-01T00:00:00.000Z";
const now = Date.parse("2026-09-15T00:00:00.000Z");
const row = (observation: unknown) => ({ collector: "db", evidence: { version: 1, fields: { policies: observation } } });

describe("safe evidence coverage projection", () => {
  it("shows per-field dates rather than borrowing the row's updated time", () => {
    const result = summarizeEvidence([{ ...row({ recordedAt, completeness: "partial" }), updated_at: new Date(now).toISOString() }], now);
    expect(result).toEqual([{ label: "Database access rules", recordedAt, completeness: "partial" }]);
  });
  it("keeps legacy evidence unknown", () => {
    expect(summarizeEvidence([{ collector: "source", evidence: null }], now)).toEqual([
      { label: "Repository evidence", recordedAt: null, completeness: "unknown" },
    ]);
  });
  it.each(["not-a-date", "2099-01-01T00:00:00Z", null])("rejects an unusable timestamp: %s", (date) => {
    expect(summarizeEvidence([row({ recordedAt: date, completeness: "complete" })], now)[0]).toMatchObject({ recordedAt: null, completeness: "unknown" });
  });
  it("does not render raw facts, arbitrary metadata keys, or reasons", () => {
    const result = summarizeEvidence([{ collector: "db", facts: { secret: "PRIVATE" }, evidence: { version: 1, fields: {
      policies: { recordedAt, completeness: "complete", reason: "PRIVATE" },
      PRIVATE: { recordedAt, completeness: "complete" },
    } } }], now);
    expect(result).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain("PRIVATE");
  });
  it("does not interpret an unsupported metadata version", () => {
    expect(summarizeEvidence([{ collector: "db", evidence: { version: 2, fields: { policies: { recordedAt, completeness: "complete" } } } }], now)[0].completeness).toBe("unknown");
  });
  it("ignores unknown collectors and malformed rows", () => {
    expect(summarizeEvidence([null, {}, { collector: "__proto__" }, { collector: "other" }], now)).toEqual([]);
  });
});

describe("evidence coverage loading", () => {
  beforeEach(() => {
    eq.mockReset().mockResolvedValue({ data: [] });
    select.mockReset().mockReturnValue({ eq });
  });
  it("scopes the read to the authenticated user and requests only metadata", async () => {
    await expect(getEvidenceCoverage("user-a")).resolves.toEqual({ available: true, items: [] });
    expect(eq).toHaveBeenCalledWith("user_id", "user-a");
    expect(select).toHaveBeenCalledWith("collector, evidence:facts->_evidence");
  });
  it("distinguishes failed reads from no stored evidence", async () => {
    eq.mockResolvedValue({ data: null, error: { message: "unavailable" } });
    await expect(getEvidenceCoverage("user-a")).resolves.toEqual({ available: false, items: [] });
  });
  it("handles connection failures without failing the coverage page", async () => {
    eq.mockRejectedValue(new Error("offline"));
    await expect(getEvidenceCoverage("user-a")).resolves.toEqual({ available: false, items: [] });
  });
});

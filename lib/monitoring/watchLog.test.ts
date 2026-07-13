import { describe, expect, it } from "vitest";
import { annotateWatchLog } from "./watchLog";
import type { Finding } from "./findings";

const finding = (id: string, severity: Finding["severity"] = "HIGH"): Finding => ({
  id,
  severity,
  title: id,
  consequence: "",
});

describe("annotateWatchLog", () => {
  it("returns empty for no rows", () => {
    expect(annotateWatchLog([], 12)).toEqual([]);
  });

  it("marks the oldest fetched row's newCount as null (no baseline)", () => {
    const rows = [
      { trigger_source: "hourly" as const, created_at: "2026-07-13T02:00:00Z", findings: [finding("a")] },
    ];
    expect(annotateWatchLog(rows, 12)[0].newCount).toBeNull();
  });

  it("diffs by stable id against the previous (older) snapshot", () => {
    const rows = [
      {
        trigger_source: "hourly" as const,
        created_at: "2026-07-13T03:00:00Z",
        findings: [finding("a"), finding("b"), finding("c", "CRITICAL")],
      },
      {
        trigger_source: "manual" as const,
        created_at: "2026-07-13T02:00:00Z",
        findings: [finding("a")],
      },
    ];
    const [latest, seed] = annotateWatchLog(rows, 12);
    expect(latest.newCount).toBe(2);
    expect(latest.findingCount).toBe(3);
    expect(latest.criticalCount).toBe(1);
    expect(seed.newCount).toBeNull();
  });

  it("counts resolved-then-returned findings as new again, like the alert diff", () => {
    const rows = [
      { trigger_source: "hourly" as const, created_at: "t3", findings: [finding("a")] },
      { trigger_source: "hourly" as const, created_at: "t2", findings: [] },
      { trigger_source: "manual" as const, created_at: "t1", findings: [finding("a")] },
    ];
    const entries = annotateWatchLog(rows, 12);
    expect(entries[0].newCount).toBe(1); // reappeared vs. empty t2
    expect(entries[1].newCount).toBe(0); // resolved is not "new"
  });

  it("only displays displayLimit rows, using the extra row as baseline only", () => {
    const rows = [
      { trigger_source: "hourly" as const, created_at: "t3", findings: [finding("a"), finding("b")] },
      { trigger_source: "hourly" as const, created_at: "t2", findings: [finding("a")] },
      { trigger_source: "manual" as const, created_at: "t1", findings: [] },
    ];
    const entries = annotateWatchLog(rows, 2);
    expect(entries).toHaveLength(2);
    expect(entries[0].newCount).toBe(1);
    expect(entries[1].newCount).toBe(1); // t2 vs t1 baseline, even though t1 isn't displayed
  });
});

import { describe, expect, it } from "vitest";
import { parseReasonedFindings, toDeepFindingRows } from "./reasoningRun";

describe("parseReasonedFindings", () => {
  const good = JSON.stringify({
    findings: [
      { title: "IDOR on orders", severity: "CRITICAL", consequence: "Any user can edit others' orders.", location: "app/api/orders/route.ts", confidence: "medium", why: "no ownership check" },
    ],
  });

  it("parses valid findings (and strips code fences)", () => {
    expect(parseReasonedFindings("```json\n" + good + "\n```")).toHaveLength(1);
  });

  it("drops items missing required fields or with bad enums", () => {
    const bad = JSON.stringify({
      findings: [
        { title: "x", severity: "HIGH", consequence: "c", location: "l", confidence: "medium", why: "w" }, // bad severity
        { title: "y", severity: "WARNING", consequence: "c", location: "l", confidence: "sure", why: "w" }, // bad confidence
        { title: "z", severity: "INFO", consequence: "c", location: "l", confidence: "low", why: "w" }, // good
      ],
    });
    expect(parseReasonedFindings(bad)).toHaveLength(1);
  });

  it("returns [] on non-JSON or wrong shape", () => {
    expect(parseReasonedFindings("not json")).toEqual([]);
    expect(parseReasonedFindings(JSON.stringify({ nope: [] }))).toEqual([]);
  });
});

describe("toDeepFindingRows", () => {
  it("frames every finding as reasoned, not proven, with a stable id", () => {
    const rows = toDeepFindingRows([
      { title: "IDOR on orders", severity: "CRITICAL", consequence: "Bad.", location: "app/api/orders/route.ts", confidence: "medium", why: "no check" },
    ]);
    expect(rows[0].title.startsWith("Likely:")).toBe(true);
    expect(rows[0].consequence).toContain("not confirmed by an exploit");
    expect(rows[0].consequence).toContain("confidence: medium");
    expect(rows[0].finding_id).toMatch(/^github-reasoned:medium:/);
  });
});

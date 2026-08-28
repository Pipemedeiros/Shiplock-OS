import { describe, expect, it } from "vitest";
import { selectForAutoPr } from "./autoFixPr";
import type { DashboardFinding } from "./dashboardData";

function finding(over: Partial<DashboardFinding>): DashboardFinding {
  return {
    rowId: "row", id: "f1", title: "t", consequence: "c",
    severity: "CRITICAL", confidence: "corroborated", attackClass: "missing_authorization",
    entry: "/api/x", file: "app/api/x/route.ts", blastRadius: null,
    fixKind: "pr", claims: [], repository: "o/r", detectedAt: "now",
    fixPrUrl: null, fixPrNumber: null,
    ...over,
  };
}

describe("selectForAutoPr", () => {
  it("opens one for a mechanical finding without being asked", () => {
    expect(selectForAutoPr([finding({})])).toHaveLength(1);
  });

  it("never opens one for a decision that belongs to the customer", () => {
    // `manual` means the answer lives in their head. A pull request about it is
    // noise wearing the shape of help.
    expect(selectForAutoPr([finding({ fixKind: "manual" })])).toHaveLength(0);
    expect(selectForAutoPr([finding({ fixKind: "one_click" })])).toHaveLength(0);
  });

  it("never opens a second pull request for the same finding", () => {
    // The audit runs every 48 hours and on every push. Without this, a finding
    // that survives accumulates one pull request per run.
    const already = finding({ fixPrUrl: "https://github.com/o/r/pull/3", fixPrNumber: 3 });
    expect(selectForAutoPr([already])).toHaveLength(0);
  });

  it("skips a finding with no repository to open it against", () => {
    expect(selectForAutoPr([finding({ repository: null })])).toHaveLength(0);
  });

  it("caps a run, and truncates the least important end", () => {
    const many = [
      ...Array.from({ length: 8 }, (_, i) => finding({ id: `w${i}`, severity: "WARNING" })),
      finding({ id: "crit", severity: "CRITICAL" }),
    ];
    const chosen = selectForAutoPr(many);
    expect(chosen).toHaveLength(5);
    // A run that opens five pull requests and drops the critical one has
    // inverted its own priority.
    expect(chosen[0].id).toBe("crit");
  });

  it("does not spend review attention on an INFO", () => {
    expect(selectForAutoPr([finding({ severity: "INFO" })])).toHaveLength(0);
  });
});

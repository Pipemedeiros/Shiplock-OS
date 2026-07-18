import { describe, expect, it } from "vitest";
import { buildAgentBrief, type DeepBriefFinding } from "./agentBrief";
import type { LatestScan } from "@/lib/scanHistory";
import type { FullIssue } from "@/lib/types";

const scan = (full: FullIssue[]): LatestScan => ({
  issue_count: full.length, preview_issues: null, full_issues: full,
  created_at: "2026-07-17T00:00:00Z", project_url_hash: "abcdef123456",
});

const rlsIssue: FullIssue = {
  title: "Table has no RLS", severity: "CRITICAL",
  consequence: "Anyone can read every row.", fix: "Enable RLS.",
};

describe("buildAgentBrief", () => {
  it("keeps the RLS/auth do-not-auto-apply guardrail", () => {
    const md = buildAgentBrief(scan([rlsIssue]));
    expect(md).toContain("Do NOT auto-modify Row Level Security");
  });

  it("includes scan findings under the DB/config section", () => {
    const md = buildAgentBrief(scan([rlsIssue]));
    expect(md).toContain("Database & configuration findings");
    expect(md).toContain("Table has no RLS");
  });

  it("includes deep findings in their own section, most-severe first", () => {
    const deep: DeepBriefFinding[] = [
      { title: "Open redirect", severity: "WARNING", consequence: "Validate the target." },
      { title: "SQL injection", severity: "CRITICAL", consequence: "Use parameters." },
    ];
    const md = buildAgentBrief(scan([]), deep);
    expect(md).toContain("Source code & deep findings");
    expect(md).toContain("SQL injection");
    expect(md).toContain("Open redirect");
    // CRITICAL sorted before WARNING
    expect(md.indexOf("SQL injection")).toBeLessThan(md.indexOf("Open redirect"));
  });

  it("says nothing-to-do only when BOTH scan and deep findings are empty", () => {
    expect(buildAgentBrief(scan([]))).toContain("No open findings");
    expect(buildAgentBrief(scan([]), [{ title: "x", severity: "INFO", consequence: "y" }])).not.toContain("No open findings on the latest scan. Nothing");
  });
});

import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getLatestScan } from "@/lib/scanHistory";
import { getFixFindings } from "@/lib/fixes/findings";
import { buildAgentBrief, type DeepBriefFinding } from "@/lib/agentBrief";
import type { LatestScan } from "@/lib/scanHistory";

// MCP resource `shiplock://brief`: the full agent brief (scan + deep findings)
// so the agent can load the whole surface at once. PAT-authed (fix content is
// paid-gated; authMcp verifies paid).
const EMPTY_SCAN: LatestScan = {
  issue_count: 0, preview_issues: null, full_issues: [], created_at: null, project_url_hash: null,
};

export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const [latest, findings] = await Promise.all([getLatestScan(ctx.userId), getFixFindings(ctx.userId)]);
  const deep: DeepBriefFinding[] = findings
    .filter((f) => f.source !== "scan")
    .map((f) => ({ title: f.title, severity: f.severity, consequence: f.fix }));

  const markdown = buildAgentBrief(latest ?? EMPTY_SCAN, deep);
  return NextResponse.json({ markdown });
}

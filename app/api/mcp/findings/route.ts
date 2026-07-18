import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getFixFindings } from "@/lib/fixes/findings";
import { fixLane } from "@/lib/fixes/lane";

// MCP tool `list_findings`: the developer's coding agent pulls the open findings
// into context. PAT-authed. Returns metadata + lane + a fix summary; the full
// fix content comes from /api/mcp/fix.
export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const findings = await getFixFindings(ctx.userId);
  return NextResponse.json({
    findings: findings.map((f) => {
      const lane = fixLane(f);
      return {
        id: f.id,
        title: f.title,
        severity: f.severity,
        source: f.source,
        method: lane.method,
        summary: f.fix.slice(0, 400),
      };
    }),
  });
}

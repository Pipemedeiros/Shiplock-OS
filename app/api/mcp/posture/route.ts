import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getFixFindings } from "@/lib/fixes/findings";
import { getWatchStatus } from "@/lib/monitoring/watchLog";

// MCP resource `shiplock://posture`: a concise current-posture summary the agent
// can pull in. Counts only — no fix content. PAT-authed.
export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const [findings, watch] = await Promise.all([getFixFindings(ctx.userId), getWatchStatus(ctx.userId)]);
  return NextResponse.json({
    monitored: watch.enabled,
    lastScanAt: watch.lastDeepScanAt,
    openFindings: findings.length,
    openCritical: findings.filter((f) => f.severity === "CRITICAL").length,
  });
}

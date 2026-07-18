import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getFixFindings } from "@/lib/fixes/findings";
import { fixLane } from "@/lib/fixes/lane";
import { buildMigrationFix, buildCodeFix, buildDeepLink } from "@/lib/fixes/content";

// MCP tool `get_fix`: the full fix for one finding — its lane, the seed content
// (SQL/markdown), and the target file path so the agent can write it into the
// local working tree (dev reviews the git diff + commits) or call
// /api/mcp/fix/pr. deep-link findings return a URL instead of file content.
export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "Missing finding id." }, { status: 400 });

  const finding = (await getFixFindings(ctx.userId)).find((f) => f.id === id);
  if (!finding) return NextResponse.json({ error: "Finding not found." }, { status: 404 });

  const lane = fixLane(finding);

  if (lane.method === "deep-link") {
    return NextResponse.json({
      id: finding.id, title: finding.title, severity: finding.severity,
      method: lane.method, url: buildDeepLink(finding), instructions: finding.fix,
    });
  }

  const artifact = lane.method === "migration-pr" ? buildMigrationFix(finding) : buildCodeFix(finding);
  return NextResponse.json({
    id: finding.id, title: finding.title, severity: finding.severity,
    method: lane.method, targetPath: artifact.path, content: artifact.content,
    // Boundary reminder the agent should honor.
    note:
      lane.method === "migration-pr"
        ? "This is a database migration. Write it to the target path; the developer reviews the diff, commits, and their deploy applies it. Never apply DB changes to production directly."
        : "Apply the change to the target file; the developer reviews the diff and commits.",
  });
}

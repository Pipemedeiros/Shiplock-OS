import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { getFixFindings } from "@/lib/fixes/findings";
import { runFixPr } from "@/lib/fixes/prRun";

// MCP tool `open_fix_pr`: open the reviewable fix PR for one finding (for agents
// that prefer a PR over a local working-tree edit). PAT-authed. The finding is
// re-resolved server-side by id; editedContent is the agent's reviewed version.
const Body = z.object({ findingId: z.string().min(1).max(400), editedContent: z.string().max(60_000) });

export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  let parsed;
  try {
    parsed = Body.parse(await req.json());
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  const finding = (await getFixFindings(ctx.userId)).find((f) => f.id === parsed.findingId);
  if (!finding) return NextResponse.json({ error: "Finding not found." }, { status: 404 });

  try {
    const { url } = await runFixPr(ctx.userId, finding, parsed.editedContent);
    return NextResponse.json({ url });
  } catch (err) {
    const msg = err instanceof Error && /not connected|no accessible|isn't applied/i.test(err.message)
      ? err.message
      : "Could not open the fix PR.";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

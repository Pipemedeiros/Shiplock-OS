import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { isSameOrigin } from "@/lib/security/sameOrigin";
import { quotaResponse } from "@/lib/quota";

/**
 * The customer's click to open a PR for a change their own AI proposed
 * (10B-3b). Admits one receipted repair job bound to the answered task; the
 * worker re-checks the files and opens the PR. Never a merge. Poll
 * /api/fix/receipts/[id] for the outcome.
 */

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  if (!isSameOrigin(request)) {
    return NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
  }
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "Name an AI check." }, { status: 400 });

  // Resolved exactly as the preview resolves it (Q13-F).
  let resolved;
  try { resolved = await resolveRepairTarget(user.userId, { lane: "ai", taskId: id.data }); }
  catch { return NextResponse.json({ error: "Try again in a moment." }, { status: 503 }); }
  if (!resolved.ok) {
    if (resolved.code === "not_found") return NextResponse.json({ error: "That AI check was not found." }, { status: 404 });
    return NextResponse.json({ error: "This AI check has no proposed change to open." }, { status: 409 });
  }

  try {
    const receiptId = await requestRepairAction({ userId: user.userId, repositoryId: resolved.target.repositoryId,
      action: "ai-fix-pr", findingId: id.data, editedContent: null, taskId: id.data });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch (err) {
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the pull request. Try again." }, { status: 503 });
  }
}

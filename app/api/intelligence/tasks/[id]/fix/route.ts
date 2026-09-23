import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { requestRepairAction } from "@/lib/jobs/repairAction";

/**
 * The customer's click to open a PR for a change their own AI proposed
 * (10B-3b). Admits one receipted repair job bound to the answered task; the
 * worker re-checks the files and opens the PR. Never a merge. Poll
 * /api/fix/receipts/[id] for the outcome.
 */
const taskSchema = z.object({
  repository_id: z.uuid(), status: z.string(),
  result: z.object({ edits: z.array(z.unknown()) }).nullable(),
});

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  if (request.headers.get("origin") !== new URL(request.url).origin) {
    return NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
  }
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "Name an AI check." }, { status: 400 });

  const { data, error } = await getSupabaseAdmin().from("intelligence_tasks")
    .select("repository_id, status, result").eq("id", id.data).eq("user_id", user.userId).maybeSingle();
  if (error) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  const task = taskSchema.safeParse(data);
  if (!task.success) return NextResponse.json({ error: "That AI check was not found." }, { status: 404 });
  if (task.data.status !== "proposal_received" || !task.data.result?.edits.length) {
    return NextResponse.json({ error: "This AI check has no proposed change to open." }, { status: 409 });
  }

  try {
    const receiptId = await requestRepairAction({ userId: user.userId, repositoryId: task.data.repository_id,
      action: "ai-fix-pr", findingId: id.data, editedContent: null, taskId: id.data });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch {
    return NextResponse.json({ error: "Could not queue the pull request. Try again." }, { status: 503 });
  }
}

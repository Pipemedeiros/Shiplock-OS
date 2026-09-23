import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { requestRepairAction } from "@/lib/jobs/repairAction";

/**
 * The customer's "fix before merge" click on a checked pull request (8B-3).
 * Admits one receipted repair job bound to the stored review; the worker opens
 * a fix PR into that pull request's head branch. Never a merge, never a push
 * to the default branch. Poll /api/fix/receipts/[id] for the outcome.
 */
const Body = z.object({ reviewId: z.uuid(), findingId: z.string().min(1).max(400) });
const reviewSchema = z.object({
  repository_id: z.uuid(), same_repository: z.boolean().nullable(), head_ref: z.string().nullable(),
  findings: z.array(z.object({ id: z.string() })),
});

export async function POST(request: Request) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name a pull request finding." }, { status: 400 });

  const { data, error } = await getSupabaseAdmin().from("pull_request_reviews")
    .select("repository_id, same_repository, head_ref, findings")
    .eq("id", parsed.data.reviewId).eq("user_id", user.userId).maybeSingle();
  if (error) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  const review = reviewSchema.safeParse(data);
  if (!review.success || !review.data.findings.some((finding) => finding.id === parsed.data.findingId)) {
    return NextResponse.json({ error: "That finding is not on this pull request." }, { status: 404 });
  }
  if (review.data.same_repository !== true || !review.data.head_ref) {
    return NextResponse.json({ error: "This pull request comes from a fork, so ShipLock cannot push a fix to its branch." }, { status: 409 });
  }

  try {
    const receiptId = await requestRepairAction({
      userId: user.userId, repositoryId: review.data.repository_id, action: "pr-fix-pr",
      findingId: parsed.data.findingId, editedContent: null, reviewId: parsed.data.reviewId,
    });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch {
    return NextResponse.json({ error: "Could not queue the fix. Try again." }, { status: 503 });
  }
}

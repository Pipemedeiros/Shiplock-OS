import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { quotaResponse } from "@/lib/quota";

/**
 * The customer's "fix before merge" click on a checked pull request.
 * Admits one receipted repair job bound to the stored review; the worker opens
 * a fix PR into that pull request's head branch. Never a merge, never a push
 * to the default branch. Poll /api/fix/receipts/[id] for the outcome.
 */
const Body = z.object({ reviewId: z.uuid(), findingId: z.string().min(1).max(400) });

export async function POST(request: Request) {
  // Cookie-authenticated mutation: require ShipLock's own page as the origin.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name a pull request finding." }, { status: 400 });

  // Resolved exactly as the preview resolves it.
  let resolved;
  try { resolved = await resolveRepairTarget(user.userId, { lane: "pull-request", ...parsed.data }); }
  catch { return NextResponse.json({ error: "Try again in a moment." }, { status: 503 }); }
  if (!resolved.ok) {
    if (resolved.code === "fork") {
      return NextResponse.json({ error: "This pull request comes from a fork, so ShipLock cannot push a fix to its branch." }, { status: 409 });
    }
    return NextResponse.json({ error: "That finding is not on this pull request." }, { status: 404 });
  }

  try {
    const receiptId = await requestRepairAction({
      userId: user.userId, repositoryId: resolved.target.repositoryId, action: "pr-fix-pr",
      findingId: parsed.data.findingId, editedContent: null, reviewId: parsed.data.reviewId,
    });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch (err) {
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the fix. Try again." }, { status: 503 });
  }
}

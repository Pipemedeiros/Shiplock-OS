import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { quotaResponse } from "@/lib/quota";

/**
 * The customer's click to open a pull request for one Risks-board finding.
 *
 * Admits a receipted repair job; the worker opens the PR on a NEW
 * branch off the default, never a push to the default and never a merge. That
 * boundary is not a setting. Poll /api/fix/receipts/[id] for the outcome.
 */
const Body = z.object({ findingId: z.string().min(1).max(400) });

export async function POST(request: Request) {
  // Cookie-authenticated mutation: require ShipLock's own page as the origin.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name a finding." }, { status: 400 });

  // Resolved from OUR records, exactly as the preview resolves it.
  const resolved = await resolveRepairTarget(user.userId, { lane: "risk", findingId: parsed.data.findingId });
  if (!resolved.ok) {
    if (resolved.code === "not_found") return NextResponse.json({ error: "No such finding." }, { status: 404 });
    if (resolved.code === "manual") {
      return NextResponse.json(
        { error: "This one is a decision about your architecture, so there is no pull request to open." },
        { status: 409 },
      );
    }
    if (resolved.code === "already_open") return NextResponse.json({ url: resolved.url, alreadyOpen: true });
    return NextResponse.json({ error: "Select this repository again before opening a pull request." }, { status: 409 });
  }
  const { target } = resolved;

  try {
    const receiptId = await requestRepairAction({
      userId: user.userId, repositoryId: target.repositoryId, action: "risk-fix-pr",
      findingId: target.findingId!, editedContent: null,
    });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch (err) {
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the pull request. Try again." }, { status: 503 });
  }
}

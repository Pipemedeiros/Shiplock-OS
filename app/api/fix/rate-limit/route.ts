import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { quotaResponse } from "@/lib/quota";

/**
 * The customer's click to open a rate-limit pull request for one route that
 * observed traffic reached (migration 093). Admits a receipted repair
 * job; the worker re-derives the change from current evidence, adds one
 * off-by-default helper on a new branch, and never merges. Poll
 * /api/fix/receipts/[id] for the outcome.
 */
const Body = z.strictObject({
  repositoryId: z.uuid(),
  routeFile: z.string().max(300).regex(/^(?:src\/)?app\/(?:[\w.\-[\]()@]+\/)*route\.[cm]?[jt]sx?$/),
});

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name one App Router route file." }, { status: 400 });
  try {
    const receiptId = await requestRepairAction({
      userId: user.userId, repositoryId: parsed.data.repositoryId, action: "rate-limit-pr",
      findingId: `traffic:${parsed.data.routeFile}`, editedContent: null,
    });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch (err) {
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the pull request. ShipLock needs observed traffic for this repository first." }, { status: 503 });
  }
}

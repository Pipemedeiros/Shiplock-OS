import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

/**
 * The customer's click to open a pull request for one Risks-board finding.
 *
 * Admits a receipted repair job (3F-C2d); the worker opens the PR on a NEW
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

  // Read the finding from OUR record rather than from the request. The client
  // sends an id and nothing else.
  const finding = (await getOpenFindings(user.userId)).find((f) => f.id === parsed.data.findingId);
  if (!finding) return NextResponse.json({ error: "No such finding." }, { status: 404 });

  if (finding.fixKind === "manual") {
    return NextResponse.json(
      { error: "This one is a decision about your architecture, so there is no pull request to open." },
      { status: 409 },
    );
  }
  if (finding.fixPrUrl) return NextResponse.json({ url: finding.fixPrUrl, alreadyOpen: true });

  const { data: repository } = await getSupabaseAdmin().from("repositories").select("id")
    .eq("user_id", user.userId).eq("full_name", finding.repository ?? "").eq("selected", true).maybeSingle();
  if (!repository) {
    return NextResponse.json({ error: "Select this repository again before opening a pull request." }, { status: 409 });
  }

  try {
    const receiptId = await requestRepairAction({
      userId: user.userId, repositoryId: repository.id as string, action: "risk-fix-pr",
      findingId: finding.id, editedContent: null,
    });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch {
    return NextResponse.json({ error: "Could not queue the pull request. Try again." }, { status: 503 });
  }
}

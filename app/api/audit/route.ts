import { after, NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { enqueueAuditJob } from "@/lib/jobs/queue";
import { runNextAuditJob } from "@/lib/jobs/auditWorker";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

/**
 * Durably queues an audit of one selected repository and returns its run id.
 * The client polls the existing run endpoint; execution continues after the
 * response and a lost worker is reclaimed by a later worker invocation.
 */
// 60, not 300. The plan this project runs on stops a function at 60 seconds, so
// declaring 300 bought nothing and hid the real ceiling: a large repository
// would be killed with its audit_runs row still marked "running", leaving the
// customer watching a spinner for a function that no longer exists.
//
// runRepositoryAudit budgets itself against the same number and gives up
// reasoning rather than the whole run, so a big codebase returns a shorter
// audit that says on Coverage exactly what it skipped.
export const maxDuration = 60;

const Body = z.object({ repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/), requestId: z.uuid().optional() });

export async function POST(request: Request) {
  // Cookie-authenticated mutation: require ShipLock's own page as the origin.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Name a repository to audit." }, { status: 400 });
  }

  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId) {
    return NextResponse.json({ error: "Connect GitHub first." }, { status: 409 });
  }

  // The repository must already be one this account selected. Auditing an
  // arbitrary name from the body would let a caller point us at any repository
  // their installation happens to reach.
  const { data: repo } = await admin
    .from("repositories")
    .select("id, full_name")
    .eq("user_id", user.userId)
    .eq("full_name", parsed.data.repository)
    .eq("selected", true)
    .maybeSingle();

  if (!repo) {
    return NextResponse.json({ error: "That repository is not selected." }, { status: 404 });
  }

  try {
    const receipt = await enqueueAuditJob(user.userId, repo.id as string, `manual:${parsed.data.requestId ?? crypto.randomUUID()}`);
    after(async () => {
      try { await runNextAuditJob(); }
      catch (err) { console.error("[api/audit] queued worker stopped:", err instanceof Error ? err.message : "unknown error"); }
    });
    return NextResponse.json({ runId: receipt.run_id, status: "queued" }, { status: 202 });
  } catch (err) {
    // Provisional hard cap (migration 082): tell the customer, do not alarm the logs.
    if (err instanceof Error && err.message === "audit_quota_reached") {
      return NextResponse.json({ error: "You have run 20 audits in the last 24 hours, the current limit. Scheduled and pull request checks keep running; try a manual audit again later." }, { status: 429 });
    }
    console.error("[api/audit] enqueue failed:", err instanceof Error ? err.message : "unknown error");
    return NextResponse.json({ error: "The audit could not be queued." }, { status: 503 });
  }
}

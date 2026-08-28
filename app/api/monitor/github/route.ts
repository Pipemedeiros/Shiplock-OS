import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runGithubScan } from "@/lib/deep/githubRun";
import { hasProductAccess } from "@/lib/access";
import { runRepositoryAudit } from "@/lib/agent/audit";

// GitHub App webhook — re-scans a repo's source on every pull request, so the
// watch re-audits "every PR" (replacing the old deploy-webhook trigger). The
// GitHub App's webhook URL points here; auth is the App's signed payload
// (X-Hub-Signature-256, HMAC over the raw body with GITHUB_WEBHOOK_SECRET).
// Inert until the secret is set. Always 200s (GitHub retries on non-2xx and a
// scan failure must not cause a retry storm).

const RESCAN_ACTIONS = new Set(["opened", "reopened", "synchronize", "ready_for_review"]);

// How long after a source scan we collapse further push-triggered scans into
// the one that already ran. See the comment at the call site.
const COALESCE_WINDOW_MS = 10 * 60 * 1000;

function verify(raw: string, sigHeader: string | null, secret: string): boolean {
  if (!sigHeader) return false;
  const expected = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(sigHeader);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function POST(req: NextRequest) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return NextResponse.json({ ok: true }); // not configured — inert

  const raw = await req.text();
  if (!verify(raw, req.headers.get("x-hub-signature-256"), secret)) {
    return NextResponse.json({ error: "bad signature" }, { status: 401 });
  }

  const event = req.headers.get("x-github-event");
  if (event !== "pull_request") return NextResponse.json({ ok: true });

  let payload: { action?: string; installation?: { id?: number } };
  try {
    payload = JSON.parse(raw);
  } catch {
    return NextResponse.json({ ok: true });
  }

  const installationId = payload.installation?.id;
  if (!payload.action || !RESCAN_ACTIONS.has(payload.action) || !installationId) {
    return NextResponse.json({ ok: true });
  }

  // Map the installation to its (paid) owner, then re-scan.
  try {
    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("id, is_paid, last_source_scan_at")
      .eq("github_installation_id", installationId)
      .maybeSingle();

    if (!profile || !hasProductAccess(profile)) {
      return NextResponse.json({ ok: true });
    }

    // ── Coalescing window ────────────────────────────────────────────────
    // `synchronize` fires on EVERY push to an open pull request, and
    // runGithubScan scans the repo set from scratch each time. Twenty pushes
    // to one PR, or a batch of Dependabot PRs, would otherwise mean twenty
    // full re-scans — hundreds of GitHub API calls against a 5,000/hour
    // installation limit, for results that are usually identical.
    //
    // A short window collapses that burst into one scan. It costs at most
    // COALESCE_WINDOW_MS of staleness on a finding, and the hourly critical
    // pass and 48-hour deep scan both run regardless — so nothing is skipped,
    // only de-duplicated. `opened` and `reopened` bypass the window: a brand
    // new PR is the event most likely to carry genuinely new code.
    const burstable = payload.action === "synchronize" || payload.action === "ready_for_review";
    const last = profile.last_source_scan_at ? Date.parse(profile.last_source_scan_at as string) : 0;
    if (burstable && Date.now() - last < COALESCE_WINDOW_MS) {
      return NextResponse.json({ ok: true, coalesced: true });
    }

    await admin
      .from("user_profiles")
      .update({ last_source_scan_at: new Date().toISOString() })
      .eq("id", profile.id as string);

    await runGithubScan(profile.id as string, installationId);

    // Re-audit every selected repository with the repository agent as well.
    //
    // runGithubScan covers committed secrets and dependency advisories. The
    // agent is what produces attack paths, and a pull request is the moment a
    // new one is most likely to appear — a route added without the scoping its
    // six neighbours have. Running it only on a schedule would mean the check
    // that matters most arrives up to 48 hours after the code that broke it.
    //
    // Failures are logged per repository and never rethrown: one repository we
    // cannot read must not stop the others, and the webhook must answer 200
    // regardless or GitHub will retry the delivery.
    const { data: repos } = await admin
      .from("repositories")
      .select("id, full_name")
      .eq("user_id", profile.id as string)
      .eq("selected", true);

    for (const repo of repos ?? []) {
      try {
        await runRepositoryAudit({
          userId: profile.id as string,
          installationId,
          repositoryId: repo.id as string,
          fullName: repo.full_name as string,
          trigger: "pull_request",
        });
      } catch (err) {
        console.error(
          `[monitor/github] audit failed for ${repo.full_name}:`,
          err instanceof Error ? err.message : err,
        );
      }
    }
  } catch (err) {
    console.error("[monitor/github] PR re-scan failed:", err instanceof Error ? err.message : err);
  }

  return NextResponse.json({ ok: true });
}

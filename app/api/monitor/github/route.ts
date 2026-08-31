import { NextRequest, NextResponse } from "next/server";
import { after } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runGithubScan } from "@/lib/deep/githubRun";
import { hasProductAccess } from "@/lib/access";
import { runRepositoryAudit } from "@/lib/agent/audit";
import { runPullRequestCheck } from "@/lib/agent/prCheck";

// GitHub App webhook — re-scans a repo's source on every pull request, so the
// watch re-audits "every PR" (replacing the old deploy-webhook trigger). The
// GitHub App's webhook URL points here; auth is the App's signed payload
// (X-Hub-Signature-256, HMAC over the raw body with GITHUB_WEBHOOK_SECRET).
// Inert until the secret is set. Always 200s (GitHub retries on non-2xx and a
// scan failure must not cause a retry storm).
//
// The scan runs in `after()`, so the 200 goes back immediately and the work
// continues once the response is sent. GitHub allows a webhook TEN SECONDS to
// return headers, and the first real delivery this handler ever received blew
// straight through it:
//
//   pull_request.opened -> 500 ... context deadline exceeded
//     (Client.Timeout exceeded while awaiting headers)
//
// The check was still posted, because the function kept running, but GitHub had
// already recorded a failed delivery and would retry it. Retries mean duplicate
// audits and duplicate check runs on the same commit. Reading a repository
// tarball takes longer than ten seconds on its own for a large codebase, so no
// amount of tuning fits the work inside the deadline: the answer is to stop
// making GitHub wait for it.
export const maxDuration = 60;

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

  let payload: {
    action?: string;
    installation?: { id?: number };
    number?: number;
    pull_request?: { number?: number; head?: { sha?: string } };
    repository?: { full_name?: string };
  };
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

    // The merge check runs BEFORE the coalescing window below, and is never
    // skipped by it. It is the answer the developer is waiting on, it costs one
    // diff read rather than a full audit, and every push to a pull request
    // deserves its own verdict — coalescing the check would mean the second
    // push to a branch silently inherits the first push's answer.
    const ownerId = profile.id as string;
    const prNumber = payload.pull_request?.number ?? payload.number;
    const headSha = payload.pull_request?.head?.sha;
    const fullName = payload.repository?.full_name;

    if (prNumber && headSha && fullName) {
      after(async () => {
        try {
          await runPullRequestCheck({
            userId: ownerId,
            installationId,
            fullName,
            prNumber,
            headSha,
          });
        } catch (err) {
          console.error(
            "[monitor/github] merge check failed:",
            err instanceof Error ? err.message : err,
          );
        }
      });
    }

    // The rest is the expensive half: a full source scan plus a repository
    // audit per selected repo, tens of seconds on a real codebase. It runs
    // after the response for the same reason the merge check does, and is the
    // part that made GitHub time out in the first place.
    after(async () => {
      try {
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
        return; // coalesced into the scan that just ran
      }

      await admin
        .from("user_profiles")
        .update({ last_source_scan_at: new Date().toISOString() })
        .eq("id", ownerId);

      await runGithubScan(ownerId, installationId);

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
        .eq("user_id", ownerId)
        .eq("selected", true);

      for (const repo of repos ?? []) {
        try {
          await runRepositoryAudit({
            userId: ownerId,
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
        console.error(
          "[monitor/github] deferred scan failed:",
          err instanceof Error ? err.message : err,
        );
      }
    });
  } catch (err) {
    console.error("[monitor/github] PR re-scan failed:", err instanceof Error ? err.message : err);
  }

  return NextResponse.json({ ok: true });
}

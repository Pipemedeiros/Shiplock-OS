import { NextRequest, NextResponse } from "next/server";
import { after } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { hasProductAccess } from "@/lib/access";
import { enqueueAuditJob, enqueueJob, enqueuePullRequestCheck, enqueuePullRequestIntelligence } from "@/lib/jobs/queue";
import { runNextJob } from "@/lib/jobs/worker";

// GitHub App webhook — durably admits repository work for qualifying pull
// request events (replacing the old deploy-webhook trigger). The
// GitHub App's webhook URL points here; auth is the App's signed payload
// (X-Hub-Signature-256, HMAC over the raw body with GITHUB_WEBHOOK_SECRET).
// Inert until the secret is set. Durable audit/check admission happens before
// acknowledgement and returns 503 on failure so GitHub can retry. Repository +
// head-SHA idempotency makes that retry safe. Source collection is also durable;
// its multi-table write is accepted only under the worker's current lease.
//
// The opportunistic queue worker runs after acknowledgement. GitHub allows a
// webhook TEN SECONDS to
// return headers, and the first real delivery this handler ever received blew
// straight through it:
//
//   pull_request.opened -> 500 ... context deadline exceeded
//     (Client.Timeout exceeded while awaiting headers)
//
// The check was still posted, because the function kept running, but GitHub had
// already recorded a failed delivery and would retry it. Retries previously
// meant duplicate audits and check runs. Reading a repository
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

  // Map the installation to its owner, then admit any durable work.
  try {
    const admin = getSupabaseAdmin();
    const { data: profile, error: profileError } = await admin
      .from("user_profiles")
      .select("id, is_paid")
      .eq("github_installation_id", installationId)
      .maybeSingle();

    if (profileError) {
      console.error("[monitor/github] installation lookup failed");
      return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
    }
    if (!profile || !hasProductAccess(profile)) {
      return NextResponse.json({ ok: true });
    }

    // The merge check is never skipped by the coalescing window. It is the
    // answer the developer is waiting on, it costs one
    // diff read rather than a full audit, and every push to a pull request
    // deserves its own verdict — coalescing the check would mean the second
    // push to a branch silently inherits the first push's answer.
    const ownerId = profile.id as string;
    const prNumber = payload.pull_request?.number ?? payload.number;
    const headSha = payload.pull_request?.head?.sha;
    const fullName = payload.repository?.full_name;
    const burstable = payload.action === "synchronize" || payload.action === "ready_for_review";

    // Admit the expensive repository audit before acknowledging the webhook.
    // Only the repository named by GitHub is eligible, and only while it is
    // still selected by the installation owner. A repeated delivery for the
    // same head SHA receives the existing receipt transactionally.
    let repository: { id: string; lastSourceScanAt: string | null } | null = null;
    if (headSha && fullName) {
      const { data, error: repositoryError } = await admin
        .from("repositories")
        .select("id, last_source_scan_at")
        .eq("user_id", ownerId)
        .eq("full_name", fullName)
        .eq("selected", true)
        .maybeSingle();

      if (repositoryError) {
        console.error("[monitor/github] repository lookup failed");
        return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
      }
      repository = data ? {
        id: data.id as string,
        lastSourceScanAt: (data.last_source_scan_at as string | null) ?? null,
      } : null;
    }

    const last = repository?.lastSourceScanAt ? Date.parse(repository.lastSourceScanAt) : 0;
    const coalesced = burstable && Date.now() - last < COALESCE_WINDOW_MS;

    let workQueued = false;
    if (!coalesced && repository && headSha && fullName) {
      try {
        await enqueueAuditJob(
          ownerId,
          repository.id,
          `pull-request:${fullName}:${headSha}`,
          "pull_request",
        );
        workQueued = true;
      } catch {
        console.error("[monitor/github] audit admission failed");
        return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
      }
    }

    if (repository && prNumber && headSha && fullName) {
      try {
        await enqueuePullRequestCheck(
          ownerId,
          repository.id,
          `pr-check:${fullName}:${prNumber}:${headSha}`,
          prNumber,
          headSha,
        );
        // Every-PR AI scan for the customer's own host, when approved. A
        // no-op otherwise; retried with the check if admission fails.
        if (/^[a-f0-9]{40}$/i.test(headSha)) {
          await enqueuePullRequestIntelligence(ownerId, repository.id, prNumber, headSha);
        }
        workQueued = true;
      } catch {
        console.error("[monitor/github] pull request check admission failed");
        return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
      }
    }

    if (!coalesced && repository) {
      try {
        const bucket = Math.floor(Date.now() / COALESCE_WINDOW_MS);
        await enqueueJob(
          ownerId,
          repository.id,
          "source",
          `webhook-source:${repository.id}:${bucket}`,
        );
        workQueued = true;
      } catch {
        console.error("[monitor/github] source admission failed");
        return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
      }
    }

    if (workQueued) {
      after(async () => {
        try {
          await runNextJob();
        } catch {
          // The queue is the durable authority. A failed opportunistic wake
          // leaves the admitted job available to the independent worker.
          console.error("[monitor/github] worker wake failed");
        }
      });
    }

  } catch {
    console.error("[monitor/github] webhook admission failed");
    return NextResponse.json({ error: "webhook temporarily unavailable" }, { status: 503 });
  }

  return NextResponse.json({ ok: true });
}

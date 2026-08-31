import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";
import { startPassBudget, createCostEstimator } from "@/lib/monitoring/passBudget";

// This pass iterates every paid user and makes several network calls each
// (policy scan, schema inventory, auth log, dependency re-check, reasoner). The
// platform default would cut it off partway through, leaving later users
// silently unprocessed. 60s is the Hobby ceiling. Work is per-user try/catch, so
// a timeout costs the remaining users this run, not the whole pass.
export const maxDuration = 60;

/** maxDuration in milliseconds, for the wall-clock budget below. */
const MAX_DURATION_MS = maxDuration * 1_000;

// The hourly "fast" pass (item 2). Genuinely lightweight now — runs
// lib/scanner.ts's scanCriticalChecks() (RLS presence, secrets/key
// exposure, public storage buckets, service-role-key submission) via
// runMonitoringPass()'s trigger-based branching, not the full 16-check
// scanProject() the 48h pass uses. See lib/monitoring/run.ts for exactly
// how that split works and why last_monitored_at is deliberately not
// touched here.
// NO TRIGGER TODAY. The GitHub Actions workflow that called this was removed on
// 2026-08-31: it needed a CRON_SECRET repository secret that was never in sync,
// it was not firing, and it serves the superseded scan-a-Supabase-project flow
// (it selects users with monitored_project_url set, which a GitHub-first
// customer never has). The route and scanCriticalChecks are kept and tested, so
// re-adding a trigger is a workflow file and nothing more.
//
// Previously scheduled via .github/workflows/hourly-monitor.yml (GitHub Actions, not
// Vercel Cron — the Vercel project is on the Hobby plan, which only
// allows daily-frequency Cron Jobs).
export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  // Staleness order, not arbitrary order. Without it, a pass that runs out of
  // wall clock always drops the same tail — the users past the cutoff would
  // never be monitored at all, silently, while their dashboard still says
  // monitoring is on. NULLS FIRST puts never-processed users at the front so a
  // new customer doesn't wait behind the entire existing base.
  const { data: profiles, error } = await admin
    .from("user_profiles")
    .select("id, email, monitored_project_url, monitored_anon_key_encrypted, last_hourly_pass_at")
    .eq("monitoring_enabled", true)
    .not("monitored_project_url", "is", null)
    .not("monitored_anon_key_encrypted", "is", null)
    .order("last_hourly_pass_at", { ascending: true, nullsFirst: true });

  if (error) {
    console.error("[monitor/hourly] user_profiles query error:", error.message);
    return NextResponse.json({ error: "Query failed" }, { status: 500 });
  }

  let succeeded = 0;
  let failed = 0;

  // Stop deliberately before the ceiling rather than being killed at it. Being
  // killed mid-loop loses the record of what ran; stopping early reports it, and
  // the staleness ordering above guarantees whoever was deferred goes first next
  // hour. Seeded at 3s/user and revised upward from real measurements as the
  // pass runs — see passBudget.ts for why the observed worst case is the right
  // estimator here rather than the mean.
  const budget = startPassBudget(MAX_DURATION_MS);
  const cost = createCostEstimator(3_000);
  const queue = (profiles ?? []).filter(
    (p) => p.monitored_project_url && p.monitored_anon_key_encrypted
  );

  for (const [index, profile] of queue.entries()) {
    if (!budget.hasTimeFor(cost.estimate())) {
      budget.recordSkipped(queue.length - index);
      console.warn(
        `[monitor/hourly] budget exhausted after ${budget.elapsedMs()}ms — ` +
          `${queue.length - index} user(s) deferred to the next run, stalest first`
      );
      break;
    }

    const started = Date.now();
    try {
      await runMonitoringPass(
        {
          id: profile.id,
          email: profile.email,
          monitored_project_url: profile.monitored_project_url!,
          monitored_anon_key_encrypted: profile.monitored_anon_key_encrypted!,
        },
        "hourly"
      );
      succeeded++;
    } catch (err) {
      failed++;
      console.error(
        `[monitor/hourly] runMonitoringPass failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    } finally {
      cost.record(Date.now() - started);
      // Stamped even when the pass failed: this is a fairness cursor, not a
      // success record. A user whose scan reliably errors must not monopolise
      // the front of the queue forever and starve everyone behind them — the
      // failure is already logged and counted for the response.
      await admin
        .from("user_profiles")
        .update({ last_hourly_pass_at: new Date().toISOString() })
        .eq("id", profile.id)
        .then(() => {}, () => {});
    }
  }

  return NextResponse.json({
    checked: queue.length,
    succeeded,
    failed,
    deferred: budget.skippedCount(),
    elapsedMs: budget.elapsedMs(),
  });
}

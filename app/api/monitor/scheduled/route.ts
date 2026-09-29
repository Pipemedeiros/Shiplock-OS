import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { pruneOldTraffic } from "@/lib/traffic/prune";
import { pruneProviderSnapshots } from "@/lib/monitoring/snapshotRetention";
import { admitFreshnessRechecks } from "@/lib/monitoring/freshness";
import { purgeIntelligenceTasks } from "@/lib/intelligence/retention";
import { saveFacts } from "@/lib/graph/graphRun";
import { collectTrafficFacts } from "@/lib/traffic/graphFacts";
import { sendWeeklyDigest } from "@/lib/monitoring/digest";
import { withPaidFilter, BILLING_ENABLED } from "@/lib/access";
import {
  admitDueRepositoryAudits,
  admitDueMonitoringPasses,
  admitDueRepositoryDependencyChecks,
  admitDueRepositorySourceScans,
  admitDueIntelligenceScans,
} from "@/lib/jobs/scheduler";
import { enqueueJob } from "@/lib/jobs/queue";

// Provider monitoring and all repository scans are admitted into the durable
// queue. This route still performs bounded traffic aggregation, graph admission,
// weekly digests, and the parked-billing expiry sweep; those legacy duties keep
// the request ceiling relevant until their own worker packages land.
export const maxDuration = 300;

// The 48h full deep scan (item 3). Reuses vercel.json's existing daily
// 9am cron entry — this route was the missing target (the cron config
// has been pointing at a 404 since before this session). Cron itself
// runs daily; staleness is checked per user inside the handler rather
// than trying to express "every 48h" as a cron expression, which is the
// standard pattern for this; the scheduler RPC owns the cutoff and fairness.
export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  // Admit durable repository work first, before this legacy route performs any
  // notification-bearing or unfenced side effect. A scheduler retry is safe:
  // migration 062 deduplicates by repository and UTC day.
  let auditAdmission;
  let sourceAdmission;
  let dependencyAdmission;
  let monitoringAdmission;
  let intelligenceAdmission;
  try {
    const now = new Date();
    [auditAdmission, sourceAdmission, dependencyAdmission, monitoringAdmission, intelligenceAdmission] = await Promise.all([
      admitDueRepositoryAudits(now, 1_000),
      admitDueRepositorySourceScans(now, 1_000),
      admitDueRepositoryDependencyChecks(now, 1_000),
      admitDueMonitoringPasses("scheduled_48h", now, 1_000),
      // Weekly deep and windowed PR scans for the customer's own AI (10B-2c).
      admitDueIntelligenceScans(now, 1_000),
    ]);
  } catch {
    console.error("[monitor/scheduled] durable work admission failed");
    return NextResponse.json({ error: "Scheduled work could not be queued." }, { status: 503 });
  }

  // Piggyback traffic-layer retention on the existing daily cron (Hobby plan
  // allows only daily-frequency crons, so we reuse this entry rather than add
  // one). Fail-soft — never affects the monitoring result.
  const pruned = await pruneOldTraffic();
  // Same daily entry bounds customer-intelligence results (10B-1d).
  const intelligence = await purgeIntelligenceTasks();
  // And provider evidence snapshots (5A-2).
  const snapshots = await pruneProviderSnapshots();
  // Stale, failed or partial provider evidence gets one extra pass a day (Q11).
  const freshness = await admitFreshnessRechecks();

  // Traffic observations run before graph admission. Dependency rechecks were
  // admitted above as separate leased jobs. The graph itself is also leased: a
  // cron timeout cannot leave a half-written finding set, and this request never
  // performs the correlation write.
  const { data: paidUsers } = await withPaidFilter(admin.from("user_profiles").select("id"));

  let graphJobsAdmitted = 0;
  let graphAdmissionsFailed = 0;
  const graphDay = new Date().toISOString().slice(0, 10);
  for (const profile of paidUsers ?? []) {
    try {
      // Traffic facts are collected immediately before reasoning rather than on
      // their own schedule: they are the one input that changes by the minute,
      // and a stale "under attack" signal is worse than none — it would keep a
      // path marked urgent long after the attack stopped.
      const hotPaths = await collectTrafficFacts(profile.id);
      if (hotPaths.length > 0) await saveFacts(profile.id, "traffic", { hotPaths });

      const { data: repositories, error: repositoriesError } = await admin
        .from("repositories")
        .select("id")
        .eq("user_id", profile.id)
        .eq("selected", true)
        .limit(50);
      if (repositoriesError) throw new Error("Selected repositories could not be read");
      for (const repository of repositories ?? []) {
        try {
          await enqueueJob(
            profile.id as string,
            repository.id as string,
            "graph",
            `scheduled-graph:${repository.id}:${graphDay}`,
          );
          graphJobsAdmitted++;
        } catch {
          graphAdmissionsFailed++;
          console.error(`[monitor/scheduled] graph admission failed for user ${profile.id}`);
        }
      }
    } catch (err) {
      console.error(
        `[monitor/scheduled] graph admission pass failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }
  // Weekly digest (migration 038). Rides the daily cron and self-limits to once
  // a week per user, so no new schedule is needed — which matters, since the
  // Vercel plan only allows daily-frequency crons. This is the churn
  // countermeasure: alerts only fire on NEW findings, so a healthy customer
  // hears nothing for months and cannot tell "working" from "dead".
  let digestsSent = 0;
  const { data: digestCandidates } = await withPaidFilter(admin.from("user_profiles").select("id, email, last_digest_sent_at"))
    .eq("monitoring_enabled", true);

  for (const profile of digestCandidates ?? []) {
    try {
      const sent = await sendWeeklyDigest(
        profile.id as string,
        (profile.email as string | null) ?? null,
        (profile.last_digest_sent_at as string | null) ?? null
      );
      if (sent) digestsSent++;
    } catch (err) {
      console.error(
        `[monitor/scheduled] digest failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }

  // Prepaid-term expiry (migration 033). Monthly subscribers have paid_until
  // NULL and are governed by Stripe's own cancel event, so they're untouched.
  // Sweeping here rather than checking an expiry at every is_paid read site
  // keeps the paywall on the single is_paid gate — the paywall has regressed
  // before when read paths diverged (see AGENTS.md), so we don't add a second
  // source of truth. Cost is up to ~24h of grace past the end date.
  const expired = await expirePrepaidTerms();

  return NextResponse.json({
    checked: monitoringAdmission.eligible,
    succeeded: monitoringAdmission.admitted,
    failed: monitoringAdmission.failed,
    pruned: pruned.ok,
    intelligencePurged: intelligence.purged,
    providerSnapshotsPruned: snapshots.pruned,
    freshnessAdmitted: freshness.admitted,
    freshnessFailed: freshness.failed,
    monitorJobsAdmitted: monitoringAdmission.admitted,
    monitorAdmissionsFailed: monitoringAdmission.failed,
    monitorAdmissionLimited: monitoringAdmission.limited,
    sourceJobsAdmitted: sourceAdmission.admitted,
    sourceAdmissionsFailed: sourceAdmission.failed,
    sourceAdmissionLimited: sourceAdmission.limited,
    dependencyJobsAdmitted: dependencyAdmission.admitted,
    dependencyAdmissionsFailed: dependencyAdmission.failed,
    dependencyAdmissionLimited: dependencyAdmission.limited,
    intelligenceJobsAdmitted: intelligenceAdmission.admitted,
    intelligenceAdmissionsFailed: intelligenceAdmission.failed,
    intelligenceAdmissionLimited: intelligenceAdmission.limited,
    graphJobsAdmitted,
    graphAdmissionsFailed,
    digestsSent,
    // -1 means the sweep is switched off with billing, not that it found nobody.
    expired,
    auditsEligible: auditAdmission.eligible,
    auditsAdmitted: auditAdmission.admitted,
    auditAdmissionsFailed: auditAdmission.failed,
    auditAdmissionLimited: auditAdmission.limited,
  });
}

/**
 * Flips is_paid false for prepaid terms whose window has passed.
 *
 * GATED ON BILLING_ENABLED, and the gate is not cosmetic. This sweep writes
 * `is_paid: false` AND `monitoring_enabled: false` to live rows, and it ran on
 * the daily cron the whole time billing was parked. The second column is the
 * damaging one: nothing in the product sets monitoring_enabled back to true
 * outside the enrolment path in /api/scan, so a customer swept here drops out
 * of the scheduled pass permanently and silently, for a billing decision the
 * product is not currently making.
 *
 * With billing parked, is_paid is not read for access at all (hasProductAccess
 * short-circuits), so expiring it decides nothing and costs a column that is
 * hard to restore. Returns -1 to distinguish "did not run" from "ran, expired
 * nobody".
 */
async function expirePrepaidTerms(): Promise<number> {
  if (!BILLING_ENABLED) return -1;
  const admin = getSupabaseAdmin();
  const { data, error } = await admin
    .from("user_profiles")
    .update({ is_paid: false, monitoring_enabled: false })
    .eq("is_paid", true)
    .not("paid_until", "is", null)
    .lt("paid_until", new Date().toISOString())
    .select("id");

  if (error) {
    console.error("[monitor/scheduled] prepaid expiry sweep error:", error.message);
    return 0;
  }
  return data?.length ?? 0;
}

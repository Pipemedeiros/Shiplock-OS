import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";
import { pruneOldTraffic } from "@/lib/traffic/prune";
import { runPolicyScan } from "@/lib/deep/supabaseMgmtRun";
import { saveFacts } from "@/lib/graph/graphRun";
import { collectTrafficFacts } from "@/lib/traffic/graphFacts";
import { runZeroDayCheck } from "@/lib/runtime/zeroDay";
import { sendWeeklyDigest } from "@/lib/monitoring/digest";
import { withPaidFilter, BILLING_ENABLED } from "@/lib/access";
import { admitDueRepositoryAudits, admitDueRepositorySourceScans } from "@/lib/jobs/scheduler";
import { enqueueJob } from "@/lib/jobs/queue";

// This pass iterates every paid user and makes several network calls each
// (policy scan, schema inventory, auth log, dependency re-check, reasoner). The
// platform default would cut it off partway through, leaving later users
// silently unprocessed. 60s is the Hobby ceiling. Work is per-user try/catch, so
// a timeout costs the remaining users this run, not the whole pass.
export const maxDuration = 60;

const FULL_SCAN_INTERVAL_MS = 48 * 60 * 60 * 1000;

// The 48h full deep scan (item 3). Reuses vercel.json's existing daily
// 9am cron entry — this route was the missing target (the cron config
// has been pointing at a 404 since before this session). Cron itself
// runs daily; staleness is checked per user inside the handler rather
// than trying to express "every 48h" as a cron expression, which is the
// standard pattern for this (see comment on FULL_SCAN_INTERVAL_MS).
export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const cutoff = new Date(Date.now() - FULL_SCAN_INTERVAL_MS).toISOString();

  // Admit full repository audits first, before this legacy route performs any
  // notification-bearing or unfenced side effect. A scheduler retry is safe:
  // migration 062 deduplicates by repository and UTC day.
  let auditAdmission;
  let sourceAdmission;
  try {
    const now = new Date();
    [auditAdmission, sourceAdmission] = await Promise.all([
      admitDueRepositoryAudits(now, 1_000),
      admitDueRepositorySourceScans(now, 1_000),
    ]);
  } catch {
    console.error("[monitor/scheduled] audit admission failed");
    return NextResponse.json({ error: "Scheduled work could not be queued." }, { status: 503 });
  }

  const { data: profiles, error } = await admin
    .from("user_profiles")
    .select(
      // vercel_* is selected because vercelEnvCollector.appliesTo reads it. A
      // collector gated on a column this query does not select never runs, and
      // never says why.
      "id, email, monitored_project_url, monitored_anon_key_encrypted, monitored_app_url, postgres_dsn_encrypted, vercel_access_token_encrypted, vercel_team_id, last_monitored_at"
    )
    .eq("monitoring_enabled", true)
    .not("monitored_project_url", "is", null)
    .not("monitored_anon_key_encrypted", "is", null)
    .or(`last_monitored_at.is.null,last_monitored_at.lt.${cutoff}`)
    // Stalest first, for the same reason as the hourly pass: this loop can be
    // cut off by the 60s ceiling, and without an explicit order the users past
    // the cutoff are whatever Postgres returned last — in practice the same ones
    // every run, never scanned, silently. NULLS FIRST puts a never-scanned user
    // ahead of one merely due for a re-scan.
    .order("last_monitored_at", { ascending: true, nullsFirst: true });

  if (error) {
    console.error("[monitor/scheduled] user_profiles query error:", error.message);
    return NextResponse.json({ error: "Query failed" }, { status: 500 });
  }

  let succeeded = 0;
  let failed = 0;

  for (const profile of profiles ?? []) {
    if (!profile.monitored_project_url || !profile.monitored_anon_key_encrypted) continue;
    try {
      await runMonitoringPass(
        {
          id: profile.id,
          email: profile.email,
          monitored_project_url: profile.monitored_project_url,
          monitored_anon_key_encrypted: profile.monitored_anon_key_encrypted,
          // Enables the app-surface half of the pass (exposed paths, source
          // maps, secrets in the shipped bundle). Null for customers who never
          // gave us an app URL — the Supabase-side scan still runs.
          monitored_app_url: profile.monitored_app_url,
        },
        "scheduled_48h"
      );
      succeeded++;
    } catch (err) {
      failed++;
      console.error(
        `[monitor/scheduled] runMonitoringPass failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }

  // Piggyback traffic-layer retention on the existing daily cron (Hobby plan
  // allows only daily-frequency crons, so we reuse this entry rather than add
  // one). Fail-soft — never affects the monitoring result.
  const pruned = await pruneOldTraffic();

  // RLS policy pass for anyone with the read-only Supabase connection
  // (migration 034). Separate from the scan above because it needs a different
  // credential and reads policy definitions rather than probing endpoints —
  // this is the check that catches `USING (true)`, which an external scan
  // structurally cannot see. Fail-soft per user.
  let policyChecked = 0;
  const { data: connected } = await withPaidFilter(admin.from("user_profiles").select("id"))
    .not("supabase_mgmt_token_encrypted", "is", null);

  for (const profile of connected ?? []) {
    try {
      const result = await runPolicyScan(profile.id);
      if (result.ok) policyChecked++;
    } catch (err) {
      console.error(
        `[monitor/scheduled] policy scan failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }

  // Dependency and traffic observations run before graph admission. The graph
  // itself is a leased job: a cron timeout cannot leave a half-written finding
  // set, and the scheduled request never performs the correlation write.
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
      // F1: re-check known dependencies against newly-published advisories.
      // Runs on the schedule rather than on push, because the dangerous case is
      // the customer who has not shipped in a month — their code did not change,
      // the world's knowledge about it did.
      try {
        await runZeroDayCheck(profile.id);
      } catch (err) {
        console.error(
          `[monitor/scheduled] zero-day check failed for user ${profile.id}:`,
          err instanceof Error ? err.message : err
        );
      }

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
  // before when read paths diverged (see CLAUDE.md), so we don't add a second
  // source of truth. Cost is up to ~24h of grace past the end date.
  const expired = await expirePrepaidTerms();

  return NextResponse.json({
    checked: profiles?.length ?? 0,
    succeeded,
    failed,
    pruned: pruned.ok,
    policyChecked,
    sourceJobsAdmitted: sourceAdmission.admitted,
    sourceAdmissionsFailed: sourceAdmission.failed,
    sourceAdmissionLimited: sourceAdmission.limited,
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

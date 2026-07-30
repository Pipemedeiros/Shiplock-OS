import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";
import { pruneOldTraffic } from "@/lib/traffic/prune";
import { runPolicyScan } from "@/lib/deep/supabaseMgmtRun";
import { runGraphReasoner, saveFacts } from "@/lib/graph/graphRun";
import { collectTrafficFacts } from "@/lib/traffic/graphFacts";
import { runZeroDayCheck } from "@/lib/runtime/zeroDay";
import { sendWeeklyDigest } from "@/lib/monitoring/digest";

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

  const { data: profiles, error } = await admin
    .from("user_profiles")
    .select("id, email, monitored_project_url, monitored_anon_key_encrypted, monitored_app_url, last_monitored_at")
    .eq("monitoring_enabled", true)
    .not("monitored_project_url", "is", null)
    .not("monitored_anon_key_encrypted", "is", null)
    .or(`last_monitored_at.is.null,last_monitored_at.lt.${cutoff}`);

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
  const { data: connected } = await admin
    .from("user_profiles")
    .select("id")
    .eq("is_paid", true)
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

  // The reasoner runs LAST, after every collector in this pass has written its
  // facts, so it correlates the freshest picture rather than the previous one.
  // Runs for every paid user — not only the Supabase-connected ones above —
  // because route facts from the per-PR source scan can produce paths on their
  // own, and a user with GitHub connected but not Supabase should still get them.
  const { data: paidUsers } = await admin.from("user_profiles").select("id").eq("is_paid", true);

  let pathsFound = 0;
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

      const result = await runGraphReasoner(profile.id);
      pathsFound += result.newCount;
    } catch (err) {
      console.error(
        `[monitor/scheduled] graph reasoner failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }
  if (pathsFound > 0) console.log(`[monitor/scheduled] ${pathsFound} new attack paths`);

  // Weekly digest (migration 038). Rides the daily cron and self-limits to once
  // a week per user, so no new schedule is needed — which matters, since the
  // Vercel plan only allows daily-frequency crons. This is the churn
  // countermeasure: alerts only fire on NEW findings, so a healthy customer
  // hears nothing for months and cannot tell "working" from "dead".
  let digestsSent = 0;
  const { data: digestCandidates } = await admin
    .from("user_profiles")
    .select("id, email, last_digest_sent_at")
    .eq("is_paid", true)
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
    digestsSent,
    expired,
  });
}

/** Flips is_paid false for prepaid terms whose window has passed. */
async function expirePrepaidTerms(): Promise<number> {
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

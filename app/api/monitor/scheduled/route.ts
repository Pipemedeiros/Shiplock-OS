import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";
import { pruneOldTraffic } from "@/lib/traffic/prune";
import { runPolicyScan } from "@/lib/deep/supabaseMgmtRun";

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
    .select("id, email, monitored_project_url, monitored_anon_key_encrypted, last_monitored_at")
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

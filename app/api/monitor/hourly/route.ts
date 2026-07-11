import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";

// The hourly "fast" pass (item 2). Genuinely lightweight now — runs
// lib/scanner.ts's scanCriticalChecks() (RLS presence, secrets/key
// exposure, public storage buckets, service-role-key submission) via
// runMonitoringPass()'s trigger-based branching, not the full 16-check
// scanProject() the 48h pass uses. See lib/monitoring/run.ts for exactly
// how that split works and why last_monitored_at is deliberately not
// touched here.
// Scheduled via .github/workflows/hourly-monitor.yml (GitHub Actions, not
// Vercel Cron — the Vercel project is on the Hobby plan, which only
// allows daily-frequency Cron Jobs).
export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const { data: profiles, error } = await admin
    .from("user_profiles")
    .select("id, email, monitored_project_url, monitored_anon_key_encrypted")
    .eq("monitoring_enabled", true)
    .not("monitored_project_url", "is", null)
    .not("monitored_anon_key_encrypted", "is", null);

  if (error) {
    console.error("[monitor/hourly] user_profiles query error:", error.message);
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
        "hourly"
      );
      succeeded++;
    } catch (err) {
      failed++;
      console.error(
        `[monitor/hourly] runMonitoringPass failed for user ${profile.id}:`,
        err instanceof Error ? err.message : err
      );
    }
  }

  return NextResponse.json({ checked: profiles?.length ?? 0, succeeded, failed });
}

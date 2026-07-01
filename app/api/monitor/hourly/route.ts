import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";

// The hourly "fast" pass (item 2). IMPORTANT — see REMAINING_BUILD_REPORT.md
// and the follow-up flagged to the project owner: this currently runs the
// SAME full 15-check scanProject() as the 48h pass. It is not actually
// lightweight yet. "RLS presence" (the most important item in the fast-pass
// spec) is architecturally the most expensive part of scanProject() — it
// requires enumerating every table and fetching policies for each, which
// is the same work the full scan does. Making this genuinely cheap needs
// either dropping RLS from the hourly cadence (relying on the 48h pass for
// it) or extracting a lighter-weight path inside lib/scanner.ts, which
// CLAUDE.md flags as not-to-be-modified without instruction. Shipped as a
// functionally-correct placeholder (correct diffing/alerting behavior,
// just not yet cheaper to run) rather than guessing which tradeoff to make.
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

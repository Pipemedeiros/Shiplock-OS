import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring/run";

// MCP tool `run_scan`: re-scan the connected project so the agent can confirm a
// fix resolved. Reuses the monitoring pass (full "deploy"-depth scan). Returns
// the count of NEW findings vs. the last snapshot. No-op with a clear reason if
// the user hasn't connected a project yet.
export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("id, email, monitoring_enabled, monitored_project_url, monitored_anon_key_encrypted")
    .eq("id", ctx.userId)
    .maybeSingle();

  if (!profile?.monitoring_enabled || !profile.monitored_project_url || !profile.monitored_anon_key_encrypted) {
    return NextResponse.json({
      ran: false,
      reason: "No connected project to scan yet. Run a scan from the ShipLock dashboard first.",
    });
  }

  try {
    const { newFindingsCount } = await runMonitoringPass(
      {
        id: profile.id,
        email: profile.email,
        monitored_project_url: profile.monitored_project_url,
        monitored_anon_key_encrypted: profile.monitored_anon_key_encrypted,
      },
      "deploy"
    );
    return NextResponse.json({ ran: true, newFindings: newFindingsCount });
  } catch {
    return NextResponse.json({ error: "Scan failed. Try again." }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runMonitoringPass } from "@/lib/monitoring";

// Deploy-triggered re-scan. The webhook URL itself
// (/api/monitor/vercel/<token>) is the auth boundary — <token> is an
// unguessable per-user UUID (migration 020), not a shared secret we
// verify via HMAC. This is a deliberate v1 tradeoff, not an oversight:
// registering a properly HMAC-signed Vercel webhook programmatically
// requires a Vercel API token per customer (item 8, not built yet).
// Until then, a customer adds this URL manually in their own Vercel
// account's webhook settings — see REMAINING_BUILD_REPORT.md item 1.
//
// Event shape assumptions (type: "deployment.ready",
// payload.deployment.target: "production") are based on Vercel's
// published webhook docs, not yet verified against a real delivery —
// flagged for real-world testing once a customer actually wires one up.
export async function POST(req: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ received: true });
  }

  const event = body as { type?: string; payload?: { deployment?: { target?: string } } };
  const isProdReady =
    event.type === "deployment.ready" && event.payload?.deployment?.target === "production";
  if (!isProdReady) {
    return NextResponse.json({ received: true, skipped: true });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("id, email, monitoring_enabled, monitored_project_url, monitored_anon_key_encrypted")
    .eq("monitor_webhook_token", token)
    .maybeSingle();

  // Generic response regardless of why monitoring didn't run — an
  // unauthenticated caller holding a guessed/leaked token learns nothing
  // about which precondition failed.
  if (
    !profile ||
    !profile.monitoring_enabled ||
    !profile.monitored_project_url ||
    !profile.monitored_anon_key_encrypted
  ) {
    return NextResponse.json({ received: true });
  }

  try {
    await runMonitoringPass(
      {
        id: profile.id,
        email: profile.email,
        monitored_project_url: profile.monitored_project_url,
        monitored_anon_key_encrypted: profile.monitored_anon_key_encrypted,
      },
      "deploy"
    );
  } catch (err) {
    console.error("[monitor/vercel] runMonitoringPass failed:", err instanceof Error ? err.message : err);
  }

  return NextResponse.json({ received: true });
}

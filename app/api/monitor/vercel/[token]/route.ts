import { NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { enqueueMonitoringPass } from "@/lib/jobs/scheduler";

const MAX_WEBHOOK_BYTES = 128 * 1024;

// Deploy-triggered re-scan. The webhook URL itself
// (/api/monitor/vercel/<token>) is the auth boundary — <token> is an
// unguessable per-user UUID (migration 020), not a shared secret we
// verify via HMAC. This is a deliberate v1 tradeoff, not an oversight:
// registering a properly HMAC-signed Vercel webhook programmatically
// requires a Vercel API token per customer (item 8, not built yet).
// Until then, a customer adds this URL manually in their own Vercel
// account's webhook settings — see CLAUDE.md.
//
// Event shape assumptions (type: "deployment.ready",
// payload.deployment.target: "production") are based on Vercel's
// published webhook docs, not yet verified against a real delivery —
// flagged for real-world testing once a customer actually wires one up.
export async function POST(req: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  let raw: string;
  let body: unknown;
  try {
    raw = await req.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_WEBHOOK_BYTES) {
      return NextResponse.json({ received: false }, { status: 413 });
    }
    body = JSON.parse(raw);
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
  const { data: profile, error: profileError } = await admin
    .from("user_profiles")
    .select("id")
    .eq("monitor_webhook_token", token)
    .maybeSingle();

  // Generic response regardless of why monitoring didn't run — an
  // unauthenticated caller holding a guessed/leaked token learns nothing
  // about which precondition failed.
  if (profileError) {
    console.error("[monitor/vercel] webhook identity lookup failed");
    return NextResponse.json({ received: false }, { status: 503 });
  }
  if (!profile) {
    return NextResponse.json({ received: true });
  }

  try {
    const delivery = createHash("sha256").update(raw).digest("hex");
    await enqueueMonitoringPass(
      profile.id,
      "deploy",
      `deploy-monitor:${delivery}`,
    );
  } catch {
    console.error("[monitor/vercel] monitoring admission failed");
    return NextResponse.json({ received: false }, { status: 503 });
  }

  return NextResponse.json({ received: true });
}

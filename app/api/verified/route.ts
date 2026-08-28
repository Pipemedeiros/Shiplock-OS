import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { checkBadgeInstalled } from "@/lib/verified/badgeCheck";
import { hasProductAccess } from "@/lib/access";

// Owner control for the public "ShipLock Verified" report. Bearer auth (mirrors
// /api/portal), paid-only. Actions: enable (mint token + turn on), disable (turn
// off, keep token), rotate (mint a fresh token — invalidates the old link).
// Generic errors; never leaks DB internals.

type Action = "enable" | "disable" | "rotate" | "check_badge";

export async function POST(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

  const admin = getSupabaseAdmin();
  const { data: auth } = await admin.auth.getUser(token);
  if (!auth.user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

  let action: Action;
  try {
    action = ((await req.json()) as { action?: Action }).action ?? "enable";
  } catch {
    action = "enable";
  }

  // Never trust client-supplied paid state — read it.
  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid, verified_report_token, verified_report_enabled, monitored_app_url")
    .eq("id", auth.user.id)
    .maybeSingle();

  if (!profile || !hasProductAccess(profile)) {
    return NextResponse.json({ error: "A subscription is required." }, { status: 402 });
  }

  // Badge install verification — confirms the customer's own site actually
  // links to their report. Read-only, fail-soft (see lib/verified/badgeCheck).
  if (action === "check_badge") {
    if (!profile.verified_report_token || !profile.verified_report_enabled) {
      return NextResponse.json({ error: "Turn the report on first." }, { status: 400 });
    }
    const appUrl = profile.monitored_app_url as string | null;
    if (!appUrl) {
      return NextResponse.json({
        state: "unknown",
        detail: "We don't have your app's address on file — add it on your next scan.",
        checkedAt: new Date().toISOString(),
      });
    }
    const result = await checkBadgeInstalled(appUrl, profile.verified_report_token);
    return NextResponse.json(result);
  }

  const patch: { verified_report_enabled?: boolean; verified_report_token?: string } = {};
  if (action === "disable") {
    patch.verified_report_enabled = false;
  } else {
    // enable or rotate: ensure a token exists (mint on enable if missing, always
    // mint on rotate), and turn the report on.
    patch.verified_report_enabled = true;
    if (action === "rotate" || !profile.verified_report_token) {
      patch.verified_report_token = crypto.randomUUID();
    }
  }

  const { error } = await admin.from("user_profiles").update(patch).eq("id", auth.user.id);
  if (error) return NextResponse.json({ error: "Could not update the report." }, { status: 500 });

  const activeToken = patch.verified_report_token ?? profile.verified_report_token ?? null;
  return NextResponse.json({
    enabled: patch.verified_report_enabled,
    token: patch.verified_report_enabled ? activeToken : null,
  });
}

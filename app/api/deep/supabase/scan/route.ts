import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { runPolicyScan } from "@/lib/deep/supabaseMgmtRun";

// Runs the RLS policy scan on demand. Read-only against the customer's
// database (see lib/deep/supabaseMgmt.ts's guard) — this can never write.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "A subscription is required." }, { status: 402 });

  const result = await runPolicyScan(pro.userId);

  if (!result.ok) {
    const message =
      result.reason === "not_connected"
        ? "Connect your Supabase project first."
        : result.reason === "auth_failed"
          ? "That connection expired. Reconnect to keep policy checks running."
          : result.reason === "shape_mismatch"
            // Says plainly that this one is ours. The alternative — "try again" —
            // would be a lie that sends the customer in a loop, since retrying
            // cannot fix an API contract change. What matters most is that they
            // are NOT shown a clean result.
            ? "Your database answered in a format we don't recognise yet, so we stopped rather than show you a result we can't stand behind. This is our bug and we've been alerted."
            : "Couldn't read your policies just now. Try again in a moment.";
    return NextResponse.json({ error: message, reason: result.reason }, { status: 400 });
  }

  return NextResponse.json({ ok: true, findings: result.findings });
}

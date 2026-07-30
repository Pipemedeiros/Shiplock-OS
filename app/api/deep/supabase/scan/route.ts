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
          : "Couldn't read your policies just now. Try again in a moment.";
    return NextResponse.json({ error: message, reason: result.reason }, { status: 400 });
  }

  return NextResponse.json({ ok: true, findings: result.findings });
}

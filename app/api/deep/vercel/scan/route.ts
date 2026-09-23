import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runVercelEnvAudit } from "@/lib/deep/vercelRun";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";

// Run (or re-run) the Vercel env-var audit for the caller's connected account.
// Pro-gated server-side. Persists only new findings.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.json({ error: "Authentication required." }, { status: 403 });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("vercel_access_token_encrypted, vercel_connection_epoch, vercel_team_id")
    .eq("id", pro.userId)
    .single();

  const encryptedToken = profile?.vercel_access_token_encrypted as string | null | undefined;
  const connectionEpoch = currentConnectionEpoch(encryptedToken, profile?.vercel_connection_epoch);
  if (!encryptedToken || !connectionEpoch) {
    return NextResponse.json({ error: "Vercel is not connected." }, { status: 400 });
  }

  try {
    const { total, newCount } = await runVercelEnvAudit(
      pro.userId, encryptedToken, connectionEpoch, (profile?.vercel_team_id as string | null) ?? null
    );
    return NextResponse.json({ ok: true, total, newCount }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Scan failed. Try again." }, { status: 502 });
  }
}

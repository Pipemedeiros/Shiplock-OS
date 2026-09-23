import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { queueCustomerRecheck } from "@/lib/jobs/manualRecheck";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";

// Queue a recheck of the caller's connected Vercel account (3F-C2c-5). The
// monitor worker runs the audit under its lease; this request collects nothing.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.json({ error: "Authentication required." }, { status: 403 });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("vercel_access_token_encrypted, vercel_connection_epoch")
    .eq("id", pro.userId)
    .single();

  const encryptedToken = profile?.vercel_access_token_encrypted as string | null | undefined;
  const connectionEpoch = currentConnectionEpoch(encryptedToken, profile?.vercel_connection_epoch);
  if (!encryptedToken || !connectionEpoch) {
    return NextResponse.json({ error: "Vercel is not connected." }, { status: 400 });
  }

  try {
    await queueCustomerRecheck(pro.userId, "vercel");
    return NextResponse.json({ ok: true, status: "queued" }, { status: 202, headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "The recheck could not be queued. Try again." }, { status: 503 });
  }
}

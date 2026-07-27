import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";

// Drops the Supabase Management connection. Clears every stored credential —
// disconnect means the token is gone, not just flagged inactive. Existing
// policy findings are archived, since we can no longer verify them.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "A subscription is required." }, { status: 402 });

  const admin = getSupabaseAdmin();
  const { error } = await admin
    .from("user_profiles")
    .update({
      supabase_mgmt_token_encrypted: null,
      supabase_mgmt_refresh_encrypted: null,
      supabase_mgmt_expires_at: null,
      supabase_mgmt_project_ref: null,
      supabase_mgmt_connected_at: null,
    })
    .eq("id", pro.userId);

  if (error) return NextResponse.json({ error: "Could not disconnect." }, { status: 500 });

  await admin
    .from("deep_findings")
    .update({ archived_at: new Date().toISOString() })
    .eq("user_id", pro.userId)
    .eq("source", "policy")
    .is("archived_at", null);

  return NextResponse.json({ connected: false });
}

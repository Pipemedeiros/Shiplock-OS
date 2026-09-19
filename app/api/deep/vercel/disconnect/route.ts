import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";

// Disconnect Vercel. Same established behavior as GitHub: ARCHIVE the source's
// findings (retain history, hide from active view) and PURGE the stored
// credential immediately — no orphaned access token left behind.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.json({ error: "Pro subscription required." }, { status: 403 });
  }

  const admin = getSupabaseAdmin();

  // Purge the encrypted token + all Vercel connection fields first.
  const { error: purgeErr } = await admin
    .from("user_profiles")
    .update({
      vercel_access_token_encrypted: null,
      vercel_team_id: null,
      vercel_config_id: null,
      vercel_connected_at: null,
    })
    .eq("id", pro.userId);
  if (purgeErr) {
    return NextResponse.json({ error: "Disconnect failed. Try again." }, { status: 500 });
  }

  // Purge the evidence relationship as well as the credential. Admission also
  // checks the current credential/installation, so failed cleanup cannot make
  // a disconnected installation's retained context admissible again.
  const [{ error: linksError }, { error: factsError }] = await Promise.all([
    admin.from("provider_repository_links").delete().eq("user_id", pro.userId).eq("provider", "vercel"),
    admin.from("graph_facts").delete().eq("user_id", pro.userId).eq("collector", "runtime"),
  ]);
  if (linksError || factsError) {
    return NextResponse.json({ error: "Disconnected, but evidence cleanup failed. Try again." }, { status: 500 });
  }

  // Archive (not delete) the source's currently-active findings.
  await admin
    .from("deep_findings")
    .update({ archived_at: new Date().toISOString() })
    .eq("user_id", pro.userId)
    .eq("source", "vercel")
    .is("archived_at", null);

  return NextResponse.json({ ok: true });
}

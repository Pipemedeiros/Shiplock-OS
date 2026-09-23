import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

// Disconnect GitHub. Same established behavior as Vercel: ARCHIVE the source's
// findings (retain history, hide from active view) and PURGE the stored
// installation id. Note: this only forgets the installation on our side — the
// user should also uninstall the App from their GitHub account to fully revoke.
export async function POST(request: Request) {
  // Cookie-authenticated mutation: require ShipLock's own page as the origin.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.json({ error: "Authentication required." }, { status: 403 });
  }

  const admin = getSupabaseAdmin();

  const { error: purgeErr } = await admin
    .from("user_profiles")
    .update({ github_installation_id: null, github_connected_at: null })
    .eq("id", pro.userId);
  if (purgeErr) {
    return NextResponse.json({ error: "Disconnect failed. Try again." }, { status: 500 });
  }

  await admin
    .from("deep_findings")
    .update({ archived_at: new Date().toISOString() })
    .eq("user_id", pro.userId)
    .eq("source", "github")
    .is("archived_at", null);

  return NextResponse.json({ ok: true });
}

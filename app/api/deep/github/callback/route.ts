import { NextRequest, NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";

// GitHub App post-install redirect target. GitHub appends
// ?installation_id=&setup_action=install. Pro-gated server-side so a
// free/signed-out caller can't land a connection with a crafted URL. We store
// only the installation_id (not itself a secret — the App private key, held in
// env, is what matters); repo reads mint short-lived tokens on demand.
export async function GET(req: NextRequest) {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard?github=forbidden`, { status: 303 });
  }

  const installationId = req.nextUrl.searchParams.get("installation_id");
  if (!installationId) {
    return NextResponse.redirect(`${base}/dashboard?github=error`, { status: 303 });
  }

  try {
    const admin = getSupabaseAdmin();
    const { error } = await admin
      .from("user_profiles")
      .update({
        github_installation_id: Number(installationId),
        github_connected_at: new Date().toISOString(),
      })
      .eq("id", pro.userId);
    if (error) return NextResponse.redirect(`${base}/dashboard?github=error`, { status: 303 });
  } catch {
    return NextResponse.redirect(`${base}/dashboard?github=error`, { status: 303 });
  }

  return NextResponse.redirect(`${base}/dashboard?github=connected`, { status: 303 });
}

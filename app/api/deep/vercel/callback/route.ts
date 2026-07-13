import { NextRequest, NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { encrypt } from "@/lib/crypto";
import { exchangeCodeForToken } from "@/lib/deep/vercel";

// Vercel integration install redirect target. Receives ?code=&teamId=&next=…
// after a Pro user installs the ShipLock integration (read-only, selected
// projects). Pro-gated SERVER-SIDE: a free/signed-out caller cannot land a
// connection here even with a crafted URL. The access token is stored
// encrypted; the plaintext token never touches the DB or logs.
export async function GET(req: NextRequest) {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard?vercel=forbidden`, { status: 303 });
  }

  const code = req.nextUrl.searchParams.get("code");
  if (!code) {
    return NextResponse.redirect(`${base}/dashboard?vercel=error`, { status: 303 });
  }

  try {
    const token = await exchangeCodeForToken(code);
    const admin = getSupabaseAdmin();
    const { error } = await admin
      .from("user_profiles")
      .update({
        vercel_access_token_encrypted: encrypt(token.accessToken),
        vercel_team_id: token.teamId,
        vercel_config_id: token.configurationId,
        vercel_connected_at: new Date().toISOString(),
      })
      .eq("id", pro.userId);
    if (error) return NextResponse.redirect(`${base}/dashboard?vercel=error`, { status: 303 });
  } catch {
    return NextResponse.redirect(`${base}/dashboard?vercel=error`, { status: 303 });
  }

  // If Vercel supplied a `next` URL (popup flow), bounce back there to close the
  // install popup — but only if it's a Vercel or own-origin URL, never an
  // attacker-controlled destination (open-redirect guard).
  const next = req.nextUrl.searchParams.get("next");
  const safeNext =
    next && /^https:\/\/([a-z0-9-]+\.)*vercel\.com\//i.test(next) === true ? next :
    next && base && next.startsWith(base) ? next :
    `${base}/dashboard?vercel=connected`;
  return NextResponse.redirect(safeNext, { status: 303 });
}

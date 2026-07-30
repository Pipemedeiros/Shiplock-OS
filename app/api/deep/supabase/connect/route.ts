import { NextResponse } from "next/server";
import { randomBytes } from "crypto";
import { cookies } from "next/headers";
import { requireProUser } from "@/lib/deep/proGate";
import { authorizeUrl, isSupabaseMgmtConfigured } from "@/lib/deep/supabaseMgmt";

// Starts the read-only Supabase Management API connection. Pro-gated, and
// CSRF-protected with a state nonce we store in an httpOnly cookie and verify
// on the way back — without it, an attacker could complete an OAuth flow into
// somebody else's account.
export async function GET() {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";

  if (!isSupabaseMgmtConfigured()) {
    return NextResponse.redirect(`${base}/dashboard/settings?supabase=unavailable`, { status: 303 });
  }

  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard/settings?supabase=forbidden`, { status: 303 });
  }

  const state = randomBytes(32).toString("hex");
  const jar = await cookies();
  jar.set("sl_sb_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 600, // ten minutes is plenty to click "authorise"
  });

  return NextResponse.redirect(authorizeUrl(state, base), { status: 303 });
}

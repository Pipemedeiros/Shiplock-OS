import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { isVercelConfigured, vercelInstallUrl } from "@/lib/deep/vercel";

/**
 * Sends the customer to Vercel to install the integration.
 *
 * Unlike the Supabase connector there is no state nonce to mint here, because
 * Vercel owns the install flow and hands back a code to the callback, which is
 * where the pro gate and the token exchange happen. This route exists so the
 * dashboard has one place to link to, and so an unconfigured deployment sends
 * nobody to a marketplace page that does not exist.
 */
export async function GET() {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";

  if (!isVercelConfigured()) {
    return NextResponse.redirect(`${base}/dashboard/settings?vercel=unavailable`, { status: 303 });
  }

  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard/settings?vercel=forbidden`, { status: 303 });
  }

  return NextResponse.redirect(vercelInstallUrl(), { status: 303 });
}

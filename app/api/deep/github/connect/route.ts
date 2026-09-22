import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { env } from "@/lib/env";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  GITHUB_INSTALL_COOKIE,
  GITHUB_INSTALL_TTL_SECONDS,
  hashGithubInstallNonce,
  newGithubInstallNonce,
} from "@/lib/githubInstallState";

// Kick off the GitHub App install. Pro-gated server-side. Redirects to the
// App's public install page; GitHub sends the user to our callback with an
// installation_id once they pick which repos to grant. Repository collection
// is read-only; separately approved fix actions need branch/PR write scope. Returns 400
// if the App isn't registered yet (GITHUB_APP_SLUG unset — see CLAUDE.md).
export async function GET() {
  const base = env.NEXT_PUBLIC_APP_URL;
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard?github=forbidden`, { status: 303 });
  }
  if (!env.GITHUB_APP_SLUG) {
    return NextResponse.redirect(`${base}/dashboard?github=unconfigured`, { status: 303 });
  }
  const nonce = newGithubInstallNonce();
  const { data, error } = await getSupabaseAdmin().rpc("begin_github_install", {
    p_user: pro.userId,
    p_nonce_hash: hashGithubInstallNonce(nonce),
  });
  if (error || data !== true) {
    return NextResponse.redirect(`${base}/onboarding?github=error`, { status: 303 });
  }

  const response = NextResponse.redirect(
    `https://github.com/apps/${env.GITHUB_APP_SLUG}/installations/new`,
    { status: 303 },
  );
  response.cookies.set(GITHUB_INSTALL_COOKIE, nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: base.startsWith("https://"),
    path: "/",
    maxAge: GITHUB_INSTALL_TTL_SECONDS,
  });
  return response;
}

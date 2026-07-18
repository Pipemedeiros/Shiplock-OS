import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { env } from "@/lib/env";

// Kick off the GitHub App install. Pro-gated server-side. Redirects to the
// App's public install page; GitHub sends the user to our callback with an
// installation_id once they pick which repos to grant (read-only). Returns 400
// if the App isn't registered yet (GITHUB_APP_SLUG unset — see ROADMAP.md).
export async function GET() {
  const base = env.NEXT_PUBLIC_APP_URL;
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.redirect(`${base}/dashboard?github=forbidden`, { status: 303 });
  }
  if (!env.GITHUB_APP_SLUG) {
    return NextResponse.redirect(`${base}/dashboard?github=unconfigured`, { status: 303 });
  }
  return NextResponse.redirect(`https://github.com/apps/${env.GITHUB_APP_SLUG}/installations/new`, { status: 303 });
}

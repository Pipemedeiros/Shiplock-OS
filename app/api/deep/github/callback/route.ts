import { NextRequest, NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationAccess, missingInstallationPermissions } from "@/lib/deep/github";
import { GITHUB_INSTALL_COOKIE, hashGithubInstallNonce } from "@/lib/githubInstallState";

// GitHub App post-install redirect target. GitHub appends
// ?installation_id=&setup_action=install. Pro-gated server-side so a
// free/signed-out caller can't land a connection with a crafted URL. We store
// only the installation_id (not itself a secret — the App private key, held in
// env, is what matters); repo reads mint short-lived tokens on demand.
//
// Success returns to /onboarding, not /dashboard. Installing the App is step
// one of a three-step journey and picking repositories is step two; landing on
// an empty dashboard drops the customer between them, with nothing selected and
// no audit ever started. A failure still goes to the dashboard, which is where
// a signed-in customer with no working connection belongs.
export async function GET(req: NextRequest) {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "";
  const redirect = (path: string) => {
    const response = NextResponse.redirect(`${base}${path}`, { status: 303 });
    response.cookies.delete(GITHUB_INSTALL_COOKIE);
    return response;
  };
  const pro = await requireProUser();
  if (!pro) {
    return redirect("/dashboard?github=forbidden");
  }

  const installationId = req.nextUrl.searchParams.get("installation_id");
  const nonce = req.cookies.get(GITHUB_INSTALL_COOKIE)?.value;
  if (!installationId || !/^[1-9][0-9]*$/.test(installationId) || !nonce) {
    return redirect("/onboarding?github=error");
  }

  try {
    // Verify the installed App can perform exactly what onboarding promised.
    // Contents write is needed only for new fix branches; ShipLock never writes
    // or merges the default branch.
    const access = await getInstallationAccess(installationId);
    if (missingInstallationPermissions(access.permissions).length > 0) {
      return redirect("/onboarding?github=permissions");
    }

    const admin = getSupabaseAdmin();
    const { data, error } = await admin.rpc("complete_github_install", {
      p_user: pro.userId,
      p_nonce_hash: hashGithubInstallNonce(nonce),
      p_installation: installationId,
    });
    if (error || data !== true) return redirect("/onboarding?github=error");
  } catch {
    return redirect("/onboarding?github=error");
  }

  return redirect("/onboarding?github=connected");
}

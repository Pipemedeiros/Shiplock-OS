import Link from "next/link";
import { redirect } from "next/navigation";
import { LockMark } from "@/components/d/Brand";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { getSupabaseAdmin } from "@/lib/supabase";
import { mfaDecision } from "@/lib/mfa";
import { OnboardingFlow } from "@/components/v3/OnboardingFlow";
import { getInstallationToken, listRepos } from "@/lib/deep/github";

export const metadata = {
  title: "Get started",
  robots: { index: false, follow: false },
};

/**
 * GitHub is the only required connection.
 *
 * The stack step that follows repository selection reports what we read out of
 * the code. The MVP does not connect to providers (owner decision 2026-08-31),
 * so there is no connection state to load here.
 *
 * There is no plan gate here: while the MVP is open, anyone signed in can run
 * an audit. Signing in is still required, because the next thing that happens
 * is that we read their private source code.
 */
export default async function Onboarding() {
  const supabase = await getSupabaseServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/auth?next=/onboarding");
  // Two-step sign-in (lib/mfa.ts): this page lists private repositories, so a
  // user with an authenticator enters the code first. getUser's factors are
  // the auth server's answer; an unreadable level fails closed.
  const { data: claimData, error: claimError } = await supabase.auth.getClaims();
  if (mfaDecision(claimError ? undefined : claimData?.claims?.aal, user.factors ?? []) !== "ok") redirect("/auth/mfa?next=/onboarding");

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.id)
    .single();

  const installationId = profile?.github_installation_id as number | null;

  // Read the repository list here rather than from an effect: it is one round
  // trip either way, and doing it on the server means the picker is populated
  // on first paint instead of flashing an empty state.
  let repositories: Awaited<ReturnType<typeof listRepos>> = [];
  let listError: string | null = null;
  let selected = new Set<string>();

  if (installationId) {
    const { data: stored } = await admin
      .from("repositories")
      .select("full_name, selected")
      .eq("user_id", user.id)
      .eq("selected", true);
    selected = new Set((stored ?? []).map((r) => r.full_name as string));

    try {
      repositories = await listRepos(await getInstallationToken(installationId));
    } catch {
      // Never fall back to the stored list: a transport failure that renders as
      // a short list looks exactly like an installation that lost access.
      listError = "Could not reach GitHub just now. Reload to try again.";
    }
  }

  return (
    <main className="v3">
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
            <Link href="/dashboard" className="v3-nav-links">Skip to dashboard</Link>
          </nav>
        </div>
      </div>

      <OnboardingFlow
        connected={Boolean(installationId)}
        listError={listError}
        initialRepos={repositories.map((r) => ({
          fullName: r.fullName,
          defaultBranch: r.defaultBranch,
          isPrivate: r.isPrivate,
          selected: selected.has(r.fullName),
          lastAuditAt: null,
        }))}
      />
    </main>
  );
}

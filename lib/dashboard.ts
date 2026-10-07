// Shared dashboard loaders. The dashboard is four pages now (Overview,
// Findings, Watch, Settings) and several of them need the same handful of
// facts, so the queries live here once rather than being copy-pasted per page.
//
// Paywall rule is unchanged and still enforced here, not in the UI: full_issues
// is only ever read through the service-role client and only ever returned when
// the CURRENT caller is paid — see lib/scanHistory.ts and AGENTS.md.

import { cache } from "react";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { getSupabaseAdmin } from "@/lib/supabase";
import { checkMfa } from "@/lib/mfa";

export interface DashboardSession {
  userId: string;
  email: string | undefined;
  provider: string;
  isPaid: boolean;
}

/**
 * Auth gate + paid status. Every dashboard page and the layout call this;
 * redirects to /auth when there's no session.
 */
// cache(): the layout and the page both call this; per request it now runs once
// (one auth check and one profile read instead of two of each).
export const requireDashboardSession = cache(async (): Promise<DashboardSession> => {
  const supabase = await getSupabaseServer();
  // getClaims verifies the access token locally against the project's ES256
  // key (JWKS cached), so a click no longer waits on the auth server. It
  // refreshes a token about to expire, and rejects a bad signature or an
  // expired token. PostgREST trusts the same token for RLS, so the boundary
  // is unchanged; getUser cost a network round trip on every page.
  const { data, error } = await supabase.auth.getClaims();
  const claims = error ? null : data?.claims;
  if (!claims?.sub) {
    redirect("/auth");
  }
  const user = { id: claims.sub, email: claims.email as string | undefined, app_metadata: claims.app_metadata as { provider?: string } | undefined };
  // Two-step sign-in (lib/mfa.ts): a user with a verified authenticator must
  // enter the code first. Factors come from the auth server; unreadable fails
  // closed to the code step, never through.
  if ((await checkMfa(user.id, claims.aal)) !== "ok") redirect("/auth/mfa");

  // Service-role, keyed on the verified subject: since 101 the user's own token
  // reads no table, so an aal1 token can never reach a row through PostgREST.
  const { data: profile } = await getSupabaseAdmin()
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();

  return {
    userId: user.id,
    email: user.email,
    provider: user.app_metadata?.provider ?? "email",
    isPaid: profile?.is_paid ?? false,
  };
});

/**
 * The monitored project's URL, plus the bare project ref parsed out of it for
 * Supabase deep links. Service-role: monitored_project_url has no SELECT grant
 * for `authenticated`.
 */
export async function getMonitoredProject(
  userId: string
): Promise<{ projectUrl: string | null; projectRef: string | null }> {
  const { data } = await getSupabaseAdmin()
    .from("user_profiles")
    .select("monitored_project_url")
    .eq("id", userId)
    .maybeSingle();

  const projectUrl = (data?.monitored_project_url as string | null | undefined) ?? null;
  if (!projectUrl) return { projectUrl: null, projectRef: null };

  try {
    return { projectUrl, projectRef: new URL(projectUrl).hostname.split(".")[0] || null };
  } catch {
    return { projectUrl, projectRef: null };
  }
}

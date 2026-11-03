import { getSupabaseServer } from "@/lib/supabaseServer";
import { getSupabaseAdmin } from "@/lib/supabase";
import { hasProductAccess } from "@/lib/access";
import { mfaDecision } from "@/lib/mfa";

// Server-side access gate for all deep-access routes. Identifies the caller
// from the session cookie, then reads their profile AUTHORITATIVELY from the DB
// via the service role — never trusts a client-supplied flag.
// Returns null when unauthenticated or when the account may not use the
// product; callers must 403.
//
// While billing is parked (lib/access.ts) every signed-in account passes. The
// identification half is unchanged and still load-bearing: these routes read a
// customer's private source code, so the caller must be someone.
interface ProContext { userId: string; email: string | null; }

/** The signed-in user with product access, or null. A user with a verified second
 * factor must have used it. */
export async function requireProUser(): Promise<ProContext | null> {
  const supabase = await getSupabaseServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;
  // Two-step sign-in (lib/mfa.ts): getUser's factors are the auth server's
  // own answer; aal comes from the verified token. Unreadable fails closed.
  const { data: claimData, error: claimError } = await supabase.auth.getClaims();
  if (mfaDecision(claimError ? undefined : claimData?.claims?.aal, user.factors ?? []) !== "ok") return null;

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();

  if (!profile || !hasProductAccess(profile)) return null;
  return { userId: user.id, email: user.email ?? null };
}

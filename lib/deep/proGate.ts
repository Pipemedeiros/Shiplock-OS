import { getSupabaseServer } from "@/lib/supabaseServer";
import { getSupabaseAdmin } from "@/lib/supabase";
import { hasProductAccess } from "@/lib/access";

// Server-side access gate for all deep-access routes. Identifies the caller
// from the session cookie, then reads their profile AUTHORITATIVELY from the DB
// via the service role — never trusts a client-supplied flag (security.md).
// Returns null when unauthenticated or when the account may not use the
// product; callers must 403.
//
// While billing is parked (lib/access.ts) every signed-in account passes. The
// identification half is unchanged and still load-bearing: these routes read a
// customer's private source code, so the caller must be someone.
export interface ProContext { userId: string; email: string | null; }

export async function requireProUser(): Promise<ProContext | null> {
  const supabase = await getSupabaseServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();

  if (!profile || !hasProductAccess(profile)) return null;
  return { userId: user.id, email: user.email ?? null };
}

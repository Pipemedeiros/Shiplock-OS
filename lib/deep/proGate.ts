import { getSupabaseServer } from "@/lib/supabaseServer";
import { getSupabaseAdmin } from "@/lib/supabase";

// Server-side Pro gate for all Phase 2 deep-access routes. Identifies the
// caller from the session cookie, then reads is_paid AUTHORITATIVELY from the
// DB via the service role — never trusts a client-supplied flag (security.md).
// Returns null when unauthenticated OR not on the paid plan; callers must 403.
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

  if (!profile?.is_paid) return null;
  return { userId: user.id, email: user.email ?? null };
}

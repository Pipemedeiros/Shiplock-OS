import { getSupabaseAdmin } from "@/lib/supabase";

// Active-block read for the serving route (GET /api/traffic/blocklist). Only
// non-expired rows — expires_at drives auto-lift, so a block silently
// disappears once its TTL passes with no separate cleanup needed. Service-role
// only (traffic_blocklist has no RLS policies, migration 025).
export async function getActiveBlocklist(userId: string): Promise<string[]> {
  const admin = getSupabaseAdmin();
  const { data, error } = await admin
    .from("traffic_blocklist")
    .select("source_id")
    .eq("user_id", userId)
    .gt("expires_at", new Date().toISOString())
    .limit(5000);

  if (error) {
    // Fail open on the serving side too — an empty list means no enforcement,
    // never a broken app.
    console.error("[traffic] blocklist read failed:", error.message);
    return [];
  }
  return (data ?? []).map((r) => r.source_id as string);
}

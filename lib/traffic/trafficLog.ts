import { getSupabaseAdmin } from "@/lib/supabase";
import type { ProtectionStatus } from "@/lib/types";

// Dashboard-facing reads for the traffic layer. Counts and metadata only —
// never request bodies, never raw IPs (source_id is already a salted hash).
// Service-role only, same access pattern as lib/monitoring/watchLog.ts.

// "Installed" = we've seen a mirrored request recently, i.e. the snippet is
// live in the customer's app and talking to us. Pure so it's unit-testable.
export const INSTALL_ACTIVE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

/** Whether the snippet counts as installed: an event seen recently. */
export function deriveInstalled(lastSeenAt: string | null, nowMs: number): boolean {
  if (!lastSeenAt) return false;
  const ts = Date.parse(lastSeenAt);
  return !Number.isNaN(ts) && nowMs - ts <= INSTALL_ACTIVE_WINDOW_MS;
}

/** Whether traffic protection is installed, when it last reported and how many
 * sources are blocked. */
export async function getProtectionStatus(userId: string): Promise<ProtectionStatus> {
  const admin = getSupabaseAdmin();

  const [{ data: profile }, { data: lastEvent }, { count: activeBlocks }] = await Promise.all([
    admin.from("user_profiles").select("traffic_ingest_token").eq("id", userId).maybeSingle(),
    admin
      .from("traffic_events")
      .select("created_at")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle(),
    admin
      .from("traffic_blocklist")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gt("expires_at", new Date().toISOString()),
  ]);

  const lastSeenAt = lastEvent?.created_at ?? null;
  return {
    installed: deriveInstalled(lastSeenAt, Date.now()),
    lastSeenAt,
    activeBlocks: activeBlocks ?? 0,
    ingestToken: profile?.traffic_ingest_token ?? null,
  };
}




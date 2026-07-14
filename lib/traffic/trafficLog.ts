import { getSupabaseAdmin } from "@/lib/supabase";
import type { BlockedSource, ProtectionStatus } from "@/lib/types";

// Dashboard-facing reads for the traffic layer. Counts and metadata only —
// never request bodies, never raw IPs (source_id is already a salted hash).
// Service-role only, same access pattern as lib/monitoring/watchLog.ts.

// "Installed" = we've seen a mirrored request recently, i.e. the snippet is
// live in the customer's app and talking to us. Pure so it's unit-testable.
export const INSTALL_ACTIVE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

export function deriveInstalled(lastSeenAt: string | null, nowMs: number): boolean {
  if (!lastSeenAt) return false;
  const ts = Date.parse(lastSeenAt);
  return !Number.isNaN(ts) && nowMs - ts <= INSTALL_ACTIVE_WINDOW_MS;
}

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

export interface ThreatAlert {
  reason: string;
  alertedAt: string;
}

// Recent flagged-but-not-blocked events (soft auth anomalies, session-hijack
// signals) from the alert log — metadata only, never the hashed source/session.
// Filters to action='alert' so blocked sources (which are also logged here for
// dedup) don't show up under "flagged, not blocked" — they belong in the
// blocklist panel.
export async function getRecentThreats(userId: string, limit = 8): Promise<ThreatAlert[]> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("traffic_alert_log")
    .select("reason, alerted_at")
    .eq("user_id", userId)
    .eq("action", "alert")
    .order("alerted_at", { ascending: false })
    .limit(limit);
  return (data ?? []).map((r) => ({ reason: r.reason as string, alertedAt: r.alerted_at as string }));
}

// Most-recent blocks (active or recently expired) for the dashboard log.
export async function getRecentBlocks(userId: string, limit = 12): Promise<BlockedSource[]> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("traffic_blocklist")
    .select("source_id, reason, severity, blocked_at, expires_at")
    .eq("user_id", userId)
    .order("blocked_at", { ascending: false })
    .limit(limit);

  return (data ?? []).map((r) => ({
    sourceId: r.source_id as string,
    reason: r.reason as string,
    severity: r.severity as BlockedSource["severity"],
    blockedAt: r.blocked_at as string,
    expiresAt: r.expires_at as string,
  }));
}

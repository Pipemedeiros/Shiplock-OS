import { getSupabaseAdmin } from "@/lib/supabase";

// Retention for the traffic layer. traffic_events gets a row per mirrored
// request, so it grows fast and must be pruned or the windowed-count queries
// slow down. Detection needs at most SESSION_WINDOW (10m); the dashboard shows
// "last seen" and a 24h install window — so 48h of events is ample. Expired
// blocklist rows are kept briefly so the dashboard can show "lifted", then
// pruned. Alert log follows the 7-day dedup horizon. Fail-soft: errors are
// logged, never thrown (called from a cron handler that must still return).
const EVENT_RETENTION_MS = 48 * 60 * 60 * 1000; // 48h
const BLOCK_GRACE_MS = 24 * 60 * 60 * 1000; // keep expired blocks 24h for the UI
const ALERT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7d

export async function pruneOldTraffic(): Promise<{ ok: boolean }> {
  const admin = getSupabaseAdmin();
  const now = Date.now();
  try {
    await admin
      .from("traffic_events")
      .delete()
      .lt("created_at", new Date(now - EVENT_RETENTION_MS).toISOString());
    await admin
      .from("traffic_blocklist")
      .delete()
      .lt("expires_at", new Date(now - BLOCK_GRACE_MS).toISOString());
    await admin
      .from("traffic_alert_log")
      .delete()
      .lt("alerted_at", new Date(now - ALERT_RETENTION_MS).toISOString());
    // Provider-log observations (2F-4) share the 48h event horizon.
    await admin
      .from("traffic_route_observations")
      .delete()
      .lt("observed_at", new Date(now - EVENT_RETENTION_MS).toISOString());
    return { ok: true };
  } catch (err) {
    console.error("[traffic] prune failed:", err instanceof Error ? err.message : err);
    return { ok: false };
  }
}

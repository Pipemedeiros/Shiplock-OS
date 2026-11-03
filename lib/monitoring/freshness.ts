import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";
import { enqueueMonitoringPass } from "@/lib/jobs/scheduler";

/**
 * Freshness rechecks. Fixed triggers leave evidence stale when
 * a pass fails or reads only part of a provider. From each account's newest
 * provider snapshot per transport (087, 088), accounts whose newest read is
 * older than 72 hours, failed, or partial get one extra monitoring pass per
 * UTC day, oldest evidence first, capped per call. Disconnected providers
 * are skipped.
 */
export type LatestRead = {
  userId: string;
  transport: "postgres-direct" | "supabase-management" | "vercel" | "app-surface" | "supabase-edge-logs";
  observedAt: string;
  completeness: "complete" | "partial" | "failed";
};

const STALE_MS = 72 * 3_600_000;

export function planFreshnessRechecks(
  reads: LatestRead[], connected: (userId: string, transport: LatestRead["transport"]) => boolean, now: number, max = 200,
): string[] {
  const newest = new Map<string, LatestRead>();
  for (const read of reads) {
    const key = `${read.userId}:${read.transport}`;
    const seen = newest.get(key);
    if (!seen || Date.parse(read.observedAt) > Date.parse(seen.observedAt)) newest.set(key, read);
  }
  const oldestDue = new Map<string, number>();
  for (const read of newest.values()) {
    if (!connected(read.userId, read.transport)) continue;
    const at = Date.parse(read.observedAt);
    if (read.completeness === "complete" && now - at <= STALE_MS) continue;
    oldestDue.set(read.userId, Math.min(oldestDue.get(read.userId) ?? Infinity, at));
  }
  return [...oldestDue.entries()].sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0])).slice(0, max).map(([userId]) => userId);
}

const snapshotRow = z.object({
  user_id: z.uuid(),
  transport: z.enum(["postgres-direct", "supabase-management", "vercel", "app-surface", "supabase-edge-logs"]),
  observed_at: z.string(), completeness: z.enum(["complete", "partial", "failed"]),
});

/** Admits the planned passes. Fail-soft: the daily cron must still answer. */
export async function admitFreshnessRechecks(now = new Date(), max = 200): Promise<{ admitted: number; failed: number }> {
  const admin = getSupabaseAdmin();
  const since = new Date(now.getTime() - 30 * 24 * 3_600_000).toISOString();
  const { data, error } = await admin.from("provider_snapshots").select("user_id, transport, observed_at, completeness")
    .gte("observed_at", since).order("observed_at", { ascending: false }).limit(5_000);
  if (error || !Array.isArray(data)) return { admitted: 0, failed: 1 };
  const reads = data.flatMap((raw) => {
    const row = snapshotRow.safeParse(raw);
    return row.success ? [{ userId: row.data.user_id, transport: row.data.transport, observedAt: row.data.observed_at, completeness: row.data.completeness }] : [];
  });
  const users = [...new Set(reads.map((r) => r.userId))];
  if (users.length === 0) return { admitted: 0, failed: 0 };
  const profiles = await admin.from("user_profiles").select(
    "id, monitoring_enabled, supabase_mgmt_token_encrypted, supabase_mgmt_connection_epoch, postgres_dsn_encrypted, postgres_connection_epoch, vercel_access_token_encrypted, vercel_connection_epoch, monitored_app_url",
  ).in("id", users);
  if (profiles.error || !Array.isArray(profiles.data)) return { admitted: 0, failed: 1 };
  const byId = new Map(profiles.data.map((p) => [p.id as string, p as Record<string, unknown>]));
  const connected = (userId: string, transport: LatestRead["transport"]) => {
    const p = byId.get(userId);
    if (!p || p.monitoring_enabled === false) return false;
    if (transport === "supabase-management" || transport === "supabase-edge-logs") {
      return currentConnectionEpoch(p.supabase_mgmt_token_encrypted, p.supabase_mgmt_connection_epoch) !== null;
    }
    if (transport === "postgres-direct") return currentConnectionEpoch(p.postgres_dsn_encrypted, p.postgres_connection_epoch) !== null;
    if (transport === "vercel") return currentConnectionEpoch(p.vercel_access_token_encrypted, p.vercel_connection_epoch) !== null;
    return typeof p.monitored_app_url === "string" && p.monitored_app_url.length > 0;
  };
  const day = now.toISOString().slice(0, 10);
  let admitted = 0, failed = 0;
  for (const userId of planFreshnessRechecks(reads, connected, now.getTime(), max)) {
    try { await enqueueMonitoringPass(userId, "scheduled_48h", `fresh:${userId}:${day}`); admitted++; }
    catch { failed++; }
  }
  return { admitted, failed };
}

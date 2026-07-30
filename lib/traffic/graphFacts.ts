import { getSupabaseAdmin } from "@/lib/supabase";

// The traffic collector's contribution to the graph.
//
// "Suspicious" here is not a vibe or a volume threshold — it means requests from
// a source this system has ALREADY judged and recorded, in traffic_alert_log or
// traffic_blocklist. That matters because of how the reasoner uses this: traffic
// raises the urgency of an existing attack path, and an urgency signal built on
// a guess would make us cry wolf about real vulnerabilities, which is the fastest
// way to get the genuine ones ignored.
//
// Everything is bounded. traffic_events is the highest-volume table we own, and
// a monitoring pass must not be able to pull an unbounded slice of it into memory
// because a customer had a busy day.

const WINDOW_HOURS = 48; // matches traffic_events retention (lib/traffic/prune.ts)
const MAX_SOURCES = 500;
const MAX_EVENTS = 5_000;
const MAX_PATHS = 20;

export interface TrafficHotPath {
  path: string;
  suspiciousRequests: number;
}

/**
 * Paths receiving traffic from sources we have already flagged.
 *
 * Returns an empty array — never a partial guess — when there is nothing
 * recorded. An empty result is meaningful to the reasoner: it means "no
 * corroboration", which leaves attack paths at their base urgency rather than
 * inflating them.
 */
export async function collectTrafficFacts(userId: string): Promise<TrafficHotPath[]> {
  const admin = getSupabaseAdmin();
  const since = new Date(Date.now() - WINDOW_HOURS * 60 * 60 * 1000).toISOString();

  const [alerted, blocked] = await Promise.all([
    admin
      .from("traffic_alert_log")
      .select("source_id")
      .eq("user_id", userId)
      .gte("alerted_at", since)
      .limit(MAX_SOURCES),
    admin.from("traffic_blocklist").select("source_id").eq("user_id", userId).limit(MAX_SOURCES),
  ]);

  const suspicious = new Set<string>();
  for (const row of [...(alerted.data ?? []), ...(blocked.data ?? [])]) {
    const id = (row as { source_id?: unknown }).source_id;
    if (typeof id === "string") suspicious.add(id);
  }
  if (suspicious.size === 0) return [];

  const { data: events } = await admin
    .from("traffic_events")
    .select("path")
    .eq("user_id", userId)
    .gte("created_at", since)
    .in("source_id", [...suspicious])
    .limit(MAX_EVENTS);

  const counts = new Map<string, number>();
  for (const row of (events ?? []) as { path?: unknown }[]) {
    if (typeof row.path !== "string") continue;
    counts.set(row.path, (counts.get(row.path) ?? 0) + 1);
  }

  return [...counts.entries()]
    .map(([path, suspiciousRequests]) => ({ path, suspiciousRequests }))
    .sort((a, b) => b.suspiciousRequests - a.suspiciousRequests || a.path.localeCompare(b.path))
    .slice(0, MAX_PATHS);
}

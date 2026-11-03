import { getSupabaseAdmin } from "@/lib/supabase";
import { idRoute } from "./detect";

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

interface TrafficHotPath {
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
export async function collectTrafficFacts(userId: string, repositoryId?: string): Promise<TrafficHotPath[]> {
  const admin = getSupabaseAdmin();
  const since = new Date(Date.now() - WINDOW_HOURS * 60 * 60 * 1000).toISOString();
  const counts = await snippetCounts(userId, repositoryId);

  // Provider-log observations for this repository (the Supabase gateway),
  // already judged per source upstream; merged with snippet counts per path.
  if (repositoryId) {
    const { data: observed } = await admin
      .from("traffic_route_observations")
      .select("path, suspicious_requests")
      .eq("user_id", userId)
      .eq("repository_id", repositoryId)
      // The snippet's own rows (X2) are already counted from traffic_events.
      .eq("source", "supabase")
      .gte("observed_at", since)
      .limit(MAX_PATHS * 2);
    for (const row of (observed ?? []) as { path?: unknown; suspicious_requests?: unknown }[]) {
      if (typeof row.path !== "string" || typeof row.suspicious_requests !== "number") continue;
      counts.set(row.path, (counts.get(row.path) ?? 0) + row.suspicious_requests);
    }
  }

  return top(counts);
}

/**
 * Snippet requests per path from sources already flagged, bound to this
 * repository through its traffic site when one is given; without one,
 * the account-scoped (legacy) view. Also what X2 writes as the repository's
 * snippet observations, so the rate-limit offer sees the snippet too.
 */
export async function collectSnippetHotPaths(userId: string, repositoryId?: string): Promise<TrafficHotPath[]> {
  return top(await snippetCounts(userId, repositoryId));
}

async function snippetCounts(userId: string, repositoryId?: string): Promise<Map<string, number>> {
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

  const counts = new Map<string, number>();
  const suspicious = new Set<string>();
  for (const row of [...(alerted.data ?? []), ...(blocked.data ?? [])]) {
    const id = (row as { source_id?: unknown }).source_id;
    if (typeof id === "string") suspicious.add(id);
  }

  if (suspicious.size > 0) {
    // With a repository, count only events bound to it through a traffic site
    //; without one, this is the account-scoped (legacy) view.
    let eventsQuery = admin
      .from("traffic_events")
      .select("path")
      .eq("user_id", userId);
    if (repositoryId) eventsQuery = eventsQuery.eq("repository_id", repositoryId);
    const { data: events } = await eventsQuery
      .gte("created_at", since)
      .in("source_id", [...suspicious])
      .limit(MAX_EVENTS);
    // Paths that differ only in a record id are one route: an id walk
    // spreads over many paths of one request each, and ranking raw paths
    // would undercount it or drop it below MAX_PATHS. The first path seen
    // stands for the route, so route matching still reads a concrete path.
    const standsFor = new Map<string, string>();
    for (const row of (events ?? []) as { path?: unknown }[]) {
      if (typeof row.path !== "string") continue;
      const pattern = idRoute(row.path)?.pattern;
      const key = pattern ? (standsFor.get(pattern) ?? standsFor.set(pattern, row.path).get(pattern)!) : row.path;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }
  return counts;
}

const top = (counts: Map<string, number>): TrafficHotPath[] => [...counts.entries()]
  .map(([path, suspiciousRequests]) => ({ path, suspiciousRequests }))
  .sort((a, b) => b.suspiciousRequests - a.suspiciousRequests || a.path.localeCompare(b.path))
  .slice(0, MAX_PATHS);

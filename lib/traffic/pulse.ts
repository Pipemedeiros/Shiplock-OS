import { getSupabaseAdmin } from "@/lib/supabase";

// The "we are watching" read.
//
// Why this exists: the dashboard previously surfaced only blocks and threats,
// and both are RARE by design — we block only when an attack is unmistakable.
// So a customer four months in sees an empty panel and concludes either "I'm
// fine" or "this thing is dead", and those two look identical from the outside.
// That is the churn mechanism for every security product, and silence-by-default
// (correct for alerting) makes it worse.
//
// The fix is not to invent alarms. It is to show the work: how many requests we
// actually inspected, from how many distinct sources, and how many we turned
// away. Those numbers are large and real every single day — unlike findings,
// which are front-loaded and then stop.
//
// Counts and metadata only. Never bodies, never raw IPs (source_id is already a
// salted hash), never query strings. Aggregation happens in Postgres
// (migration 037) rather than by pulling rows into the function: at ICP scale a
// 48h window is tens of thousands of rows, and any LIMIT would silently
// understate the headline count — the one thing this panel must never do.

const WINDOW_HOURS = 48; // traffic_events is pruned at 48h; the widest honest window
const BUCKET_COUNT = 24; // 2h per bucket

export interface TrafficPulse {
  /** Requests inspected in the window. Exact, not sampled. */
  watched: number;
  /** Distinct salted source hashes seen. */
  sources: number;
  /** Requests that came from a source we had blocked. */
  turnedAway: number;
  /** Sources currently on the blocklist. */
  activeBlocks: number;
  /** Oldest→newest counts across the window. */
  buckets: number[];
  /** A few real recent paths, for the live view. */
  recentPaths: { path: string; method: string; blocked: boolean }[];
  /** False when we've seen nothing — render an honest empty state, never a fake one. */
  hasData: boolean;
  windowHours: number;
}

export const EMPTY_PULSE: TrafficPulse = {
  watched: 0,
  sources: 0,
  turnedAway: 0,
  activeBlocks: 0,
  buckets: new Array(BUCKET_COUNT).fill(0),
  recentPaths: [],
  hasData: false,
  windowHours: WINDOW_HOURS,
};

interface PulseRow {
  watched: number;
  sources: number;
  turned_away: number;
  bucket_index: number;
  bucket_count: number;
}

export async function getTrafficPulse(userId: string): Promise<TrafficPulse> {
  const admin = getSupabaseAdmin();

  const [{ data: rows, error }, { data: blocks }, { data: recent }] = await Promise.all([
    admin.rpc("traffic_pulse", {
      p_user_id: userId,
      p_window_hours: WINDOW_HOURS,
      p_buckets: BUCKET_COUNT,
    }),
    admin
      .from("traffic_blocklist")
      .select("source_id, expires_at")
      .eq("user_id", userId),
    // Small, bounded sample purely for the scrolling live view. The headline
    // numbers above never come from this.
    admin
      .from("traffic_events")
      .select("source_id, path, method")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(12),
  ]);

  if (error) {
    console.error("[traffic] pulse aggregate failed:", error.message);
    return EMPTY_PULSE;
  }

  const pulseRows = (rows ?? []) as PulseRow[];
  if (pulseRows.length === 0) return EMPTY_PULSE;

  const buckets = new Array(BUCKET_COUNT).fill(0);
  for (const r of pulseRows) {
    if (r.bucket_index >= 0 && r.bucket_index < BUCKET_COUNT) {
      buckets[r.bucket_index] = Number(r.bucket_count) || 0;
    }
  }

  const nowMs = Date.now();
  const blockedSources = new Set((blocks ?? []).map((b) => b.source_id as string));
  const activeBlocks = (blocks ?? []).filter(
    (b) => Date.parse(b.expires_at as string) > nowMs
  ).length;

  return {
    watched: Number(pulseRows[0].watched) || 0,
    sources: Number(pulseRows[0].sources) || 0,
    turnedAway: Number(pulseRows[0].turned_away) || 0,
    activeBlocks,
    buckets,
    recentPaths: (recent ?? []).map((r) => ({
      path: (r.path as string) ?? "/",
      method: (r.method as string) ?? "GET",
      blocked: blockedSources.has(r.source_id as string),
    })),
    hasData: true,
    windowHours: WINDOW_HOURS,
  };
}

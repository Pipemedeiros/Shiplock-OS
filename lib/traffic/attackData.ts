import { getSupabaseAdmin } from "@/lib/supabase";
import { WINDOW_HOURS, type AlertRow, type BlockRow, type EventRow } from "./attackView";

/**
 * The rows the Traffic page's attack view is built from, for one customer,
 * inside the window events are kept. Only flagged sources' requests are read,
 * capped; a read error makes the whole view unavailable (unknown), never an
 * empty list that would read as "no attacks".
 */
const MAX_ALERTS = 500;
const MAX_BLOCKS = 200;
const MAX_SOURCES = 60;
const MAX_EVENTS = 4000;

export async function loadAttackRows(userId: string, now = Date.now()):
  Promise<{ available: true; now: number; alerts: AlertRow[]; blocks: BlockRow[]; events: EventRow[]; capped: boolean } | { available: false }> {
  const admin = getSupabaseAdmin();
  const since = new Date(now - WINDOW_HOURS * 3600_000).toISOString();
  const [alerts, blocks] = await Promise.all([
    admin.from("traffic_alert_log").select("source_id, reason, alerted_at, action").eq("user_id", userId)
      .gte("alerted_at", since).order("alerted_at", { ascending: false }).limit(MAX_ALERTS),
    admin.from("traffic_blocklist").select("source_id, reason, blocked_at, expires_at").eq("user_id", userId)
      .gte("blocked_at", since).order("blocked_at", { ascending: false }).limit(MAX_BLOCKS),
  ]);
  if (alerts.error || blocks.error) return { available: false };
  const alertRows = (alerts.data ?? []) as AlertRow[];
  const blockRows = (blocks.data ?? []) as BlockRow[];
  const sources = [...new Set([...alertRows, ...blockRows].map((r) => r.source_id))].slice(0, MAX_SOURCES);
  let events: EventRow[] = [];
  if (sources.length > 0) {
    const read = await admin.from("traffic_events").select("source_id, path, created_at").eq("user_id", userId)
      .in("source_id", sources).gte("created_at", since).order("created_at", { ascending: false }).limit(MAX_EVENTS);
    if (read.error) return { available: false };
    events = (read.data ?? []) as EventRow[];
  }
  // now is returned so the view uses the same instant as the window it read.
  return { available: true, now, alerts: alertRows, blocks: blockRows, events,
    capped: alertRows.length === MAX_ALERTS || events.length === MAX_EVENTS || sources.length === MAX_SOURCES };
}

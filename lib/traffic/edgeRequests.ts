import { createHmac } from "node:crypto";
import { z } from "zod";
import { computeSignals, detect, LOOKBACK_MS, FETCH_ROW_CAP, type EventRow } from "./detect";

/**
 * Traffic from Supabase's API gateway log, read with the customer's own
 * Supabase connection: no snippet, nothing in the request path. Each source is
 * judged by the same rules the snippet uses (credential stuffing, scanning,
 * floods), on its busiest window. Client IPs are hashed with a keyed daily salt
 * on arrival and never kept.
 */
const rowSchema = z.object({
  ts: z.union([z.string(), z.number()]),
  method: z.string().max(16).optional().nullable(),
  path: z.string().min(1).max(2048),
  status: z.union([z.number(), z.string()]).optional().nullable(),
  ip: z.string().min(1).max(64),
});

type EdgeJudgment = { sourceId: string; action: "block" | "alert"; reason: string };
type EdgeAnalysis =
  | { readable: false; rowsRead: number }
  | { readable: true; rowsRead: number; judged: EdgeJudgment[]; hotPaths: { path: string; suspiciousRequests: number; answered: number }[] };

const MAX_HOT_PATHS = 20;

/** A keyed hash of a visitor's IP; the address itself is never stored. */
export function hashSource(ip: string, salt: string): string {
  return createHmac("sha256", salt).update(ip.trim()).digest("hex").slice(0, 32);
}

/** A keyed, daily-rotating salt: the same visitor maps to one id per day only. */
export function dailySalt(key: string, now = new Date()): string {
  return createHmac("sha256", key).update(`edge-logs:${now.toISOString().slice(0, 10)}`).digest("hex");
}

/** Request counts and suspicious paths per hashed source from gateway log rows. */
export function analyzeEdgeRequests(raw: unknown[], salt: string): EdgeAnalysis {
  const events: { source: string; path: string; at: number; ok: boolean }[] = [];
  for (const item of raw) {
    const row = rowSchema.safeParse(item);
    if (!row.success) continue;
    const at = typeof row.data.ts === "number" ? (row.data.ts > 1e14 ? row.data.ts / 1000 : row.data.ts) : Date.parse(row.data.ts);
    if (!Number.isFinite(at)) continue;
    // Success only from a readable 2xx; anything else is not counted as answered.
    const status = Number(row.data.status);
    events.push({ source: hashSource(row.data.ip, salt), path: row.data.path.split("?")[0], at, ok: status >= 200 && status < 300 });
  }
  if (raw.length > 0 && events.length === 0) return { readable: false, rowsRead: raw.length };

  const bySource = new Map<string, { path: string; at: number; ok: boolean }[]>();
  for (const event of events) {
    const list = bySource.get(event.source) ?? [];
    list.push(event);
    bySource.set(event.source, list);
  }

  const judged: EdgeJudgment[] = [];
  const hot = new Map<string, { seen: number; answered: number }>();
  for (const [sourceId, list] of bySource) {
    list.sort((a, b) => a.at - b.at);
    let strongest: EdgeJudgment | null = null;
    let start = 0;
    for (let end = 0; end < list.length; end++) {
      while (list[end].at - list[start].at > LOOKBACK_MS) start++;
      const window: EventRow[] = list.slice(Math.max(start, end + 1 - FETCH_ROW_CAP), end + 1)
        .map((e) => ({ path: e.path, created_at: new Date(e.at).toISOString() }));
      const decision = detect(computeSignals(window, list[end].at, end + 1 - start > FETCH_ROW_CAP));
      if (decision.action === "block" || (decision.action === "alert" && !strongest)) {
        strongest = { sourceId, action: decision.action, reason: decision.reason };
        if (decision.action === "block") break;
      }
    }
    if (!strongest) continue;
    judged.push(strongest);
    for (const e of list) {
      const h = hot.get(e.path) ?? { seen: 0, answered: 0 };
      h.seen++; if (e.ok) h.answered++;
      hot.set(e.path, h);
    }
  }

  const hotPaths = [...hot.entries()]
    .map(([path, h]) => ({ path, suspiciousRequests: h.seen, answered: h.answered }))
    .sort((a, b) => b.suspiciousRequests - a.suspiciousRequests || a.path.localeCompare(b.path))
    .slice(0, MAX_HOT_PATHS);
  return { readable: true, rowsRead: raw.length, judged, hotPaths };
}

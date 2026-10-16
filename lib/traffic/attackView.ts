import type { Severity } from "@/lib/types";
import { appRouteForPath } from "./routeMatch";

/**
 * The Traffic page's model: which sources ShipLock flagged, what they did,
 * which routes they hit, and which of those routes has an open issue.
 *
 * Built only from what the snippet already sends (path, method, a salted
 * source hash, the probe category) and what detection logged; no body, no
 * query value, no address. A source is shown by a short alias of its salted
 * hash, never the hash itself. Paths are placed on a route only by the
 * audit's own route files; a path that matches none (a scanner asking for
 * /.env) stays unmatched rather than being pinned on a guessed route.
 *
 * Traffic shows attempts, not outcomes: the snippet sees a request before
 * the app answers, so nothing here says a route was compromised.
 */
export const WINDOW_HOURS = 48; // traffic_events retention (lib/traffic/prune.ts)

export type AlertRow = { source_id: string; reason: string; alerted_at: string; action: string };
export type BlockRow = { source_id: string; reason: string; blocked_at: string; expires_at: string };
export type EventRow = { source_id: string; path: string; created_at: string };
export type ViewRoute = { path: string; file: string };
export type ViewFinding = { file: string | null; title: string; severity: Severity; confirmed: boolean };

export type Attacker = {
  alias: string; sourceId: string; kinds: string[]; reasons: string[]; status: "blocked" | "flagged";
  blockedUntil: string | null; firstSeen: string; lastSeen: string; requests: number;
  routes: { pattern: string; file: string; requests: number }[]; unmatchedPaths: number;
};
export type AttackedRoute = {
  pattern: string; file: string; requests: number; attackers: number;
  finding: { title: string; severity: Severity; confirmed: boolean } | null;
};
export type AttackView = {
  attackers: Attacker[]; attackedRoutes: AttackedRoute[];
  totals: { attackers: number; blocked: number; attackedRoutes: number; attackedWithIssue: number; unmatchedPaths: number };
};

const MAX_ATTACKERS = 25;
const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };

export const sourceAlias = (sourceId: string) => `Source ${sourceId.slice(0, 4)}`;
export const attackKind = (reason: string) => reason.split(":")[0].trim() || "Flagged";

export function buildAttackView(input: {
  now: number; alerts: AlertRow[]; blocks: BlockRow[]; events: EventRow[]; routes: ViewRoute[]; findings: ViewFinding[];
}): AttackView {
  const since = input.now - WINDOW_HOURS * 3600_000;
  const recent = (iso: string) => Date.parse(iso) >= since;
  const files = input.routes.map((r) => r.file);
  const pathOf = new Map(input.routes.map((r) => [r.file, r.path]));

  const flagged = new Map<string, { reasons: Set<string>; times: string[]; blockedUntil: string | null }>();
  const entry = (id: string) => {
    if (!flagged.has(id)) flagged.set(id, { reasons: new Set(), times: [], blockedUntil: null });
    return flagged.get(id)!;
  };
  for (const a of input.alerts) if (recent(a.alerted_at)) { const e = entry(a.source_id); e.reasons.add(a.reason); e.times.push(a.alerted_at); }
  for (const b of input.blocks) {
    if (!recent(b.blocked_at)) continue;
    const e = entry(b.source_id);
    e.reasons.add(b.reason); e.times.push(b.blocked_at);
    if (Date.parse(b.expires_at) > input.now && (!e.blockedUntil || b.expires_at > e.blockedUntil)) e.blockedUntil = b.expires_at;
  }

  const matchCache = new Map<string, { file: string; pattern: string } | null>();
  const placed = (path: string) => {
    if (!matchCache.has(path)) {
      const m = appRouteForPath(path, files);
      matchCache.set(path, m ? { file: m.file, pattern: pathOf.get(m.file) ?? m.pattern } : null);
    }
    return matchCache.get(path)!;
  };

  const attackers: Attacker[] = [];
  const routeHits = new Map<string, { pattern: string; file: string; requests: number; sources: Set<string> }>();
  let unmatchedTotal = 0;
  for (const [sourceId, f] of flagged) {
    const events = input.events.filter((e) => e.source_id === sourceId && recent(e.created_at));
    const perRoute = new Map<string, { pattern: string; file: string; requests: number }>();
    let unmatched = 0;
    for (const e of events) {
      const route = placed(e.path);
      if (!route) { unmatched++; continue; }
      const r = perRoute.get(route.file) ?? { ...route, requests: 0 };
      r.requests++;
      perRoute.set(route.file, r);
      const hit = routeHits.get(route.file) ?? { ...route, requests: 0, sources: new Set<string>() };
      hit.requests++; hit.sources.add(sourceId);
      routeHits.set(route.file, hit);
    }
    unmatchedTotal += unmatched;
    const times = [...f.times, ...events.map((e) => e.created_at)].sort();
    const reasons = [...f.reasons];
    attackers.push({
      alias: sourceAlias(sourceId), sourceId, reasons, kinds: [...new Set(reasons.map(attackKind))],
      status: f.blockedUntil ? "blocked" : "flagged", blockedUntil: f.blockedUntil,
      firstSeen: times[0], lastSeen: times[times.length - 1], requests: events.length,
      routes: [...perRoute.values()].sort((a, b) => b.requests - a.requests || a.pattern.localeCompare(b.pattern)).slice(0, 5),
      unmatchedPaths: unmatched,
    });
  }
  attackers.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen) || a.alias.localeCompare(b.alias));

  const worst = new Map<string, ViewFinding>();
  for (const f of input.findings) {
    if (!f.file) continue;
    const prior = worst.get(f.file);
    const better = !prior || Number(f.confirmed) > Number(prior.confirmed)
      || (f.confirmed === prior.confirmed && (SEVERITY_RANK[f.severity] ?? 3) < (SEVERITY_RANK[prior.severity] ?? 3));
    if (better) worst.set(f.file, f);
  }
  const attackedRoutes: AttackedRoute[] = [...routeHits.values()].map((r) => {
    const f = worst.get(r.file);
    return { pattern: r.pattern, file: r.file, requests: r.requests, attackers: r.sources.size,
      finding: f ? { title: f.title, severity: f.severity, confirmed: f.confirmed } : null };
  }).sort((a, b) => Number(Boolean(b.finding?.confirmed)) - Number(Boolean(a.finding?.confirmed))
    || Number(Boolean(b.finding)) - Number(Boolean(a.finding)) || b.requests - a.requests || a.pattern.localeCompare(b.pattern));

  const shown = attackers.slice(0, MAX_ATTACKERS);
  return {
    attackers: shown, attackedRoutes,
    totals: { attackers: attackers.length, blocked: attackers.filter((a) => a.status === "blocked").length,
      attackedRoutes: attackedRoutes.length, attackedWithIssue: attackedRoutes.filter((r) => r.finding).length, unmatchedPaths: unmatchedTotal },
  };
}

import type { Severity } from "@/lib/types";
import { appRouteForPath } from "./routeMatch";
import { idRoute, isAuthPath } from "./detect";

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
 * Outcomes come only from snippets that see the answer (Express, the
 * Web-standard wrapper: a status code, migration 104). "Probably worked"
 * needs two layers to agree: the code has an open issue on the route and a
 * flagged source got success on many different record ids; or a flagged
 * source signed in after a run of failures (OWASP OAT-008). It is never
 * "compromised" and never sets an issue's status: a 200 can carry an empty
 * list. The Next.js proxy runs before the route, so its traffic is "not
 * reported", never refused and never clean.
 */
export const WINDOW_HOURS = 48; // traffic_events retention (lib/traffic/prune.ts)

export type AlertRow = { source_id: string; reason: string; alerted_at: string; action: string };
export type BlockRow = { source_id: string; reason: string; blocked_at: string; expires_at: string };
export type EventRow = { source_id: string; path: string; created_at: string; method?: string | null; status?: number | null };
export type ViewRoute = { path: string; file: string };
export type ViewFinding = { file: string | null; title: string; severity: Severity; confirmed: boolean };

export type Attacker = {
  alias: string; sourceId: string; kinds: string[]; reasons: string[]; status: "blocked" | "flagged";
  blockedUntil: string | null; firstSeen: string; lastSeen: string; requests: number;
  routes: { pattern: string; file: string; requests: number }[]; unmatchedPaths: number;
};
export type Outcome = { kind: "worked" | "answered" | "errored" | "refused" | "unreported"; detail: string };
export type AttackedRoute = {
  pattern: string; file: string; requests: number; attackers: number;
  finding: { title: string; severity: Severity; confirmed: boolean } | null;
  outcome: Outcome;
};
export type AttackView = {
  attackers: Attacker[]; attackedRoutes: AttackedRoute[];
  totals: { attackers: number; blocked: number; attackedRoutes: number; attackedWithIssue: number; probablyWorked: number; unmatchedPaths: number };
};

/** One source answered with success on this many different record ids is a walk that got records back. */
export const ANSWERED_IDS_THRESHOLD = 10;
/** Failed sign ins before a success that make it look like a guessed password. */
export const FAILURES_BEFORE_SIGN_IN = 5;

const ok = (s: number) => s >= 200 && s < 300;
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** How the app answered flagged sources on one route; pure. */
export function routeOutcome(events: readonly EventRow[], hasIssue: boolean): Outcome {
  const reported = events.filter((e): e is EventRow & { status: number } => typeof e.status === "number");
  if (reported.length === 0) {
    return { kind: "unreported", detail: "Your snippet reports requests, not how your app answered them." };
  }
  const bySource = new Map<string, (EventRow & { status: number })[]>();
  for (const e of reported) bySource.set(e.source_id, [...(bySource.get(e.source_id) ?? []), e]);

  let answeredIds = 0, signInAfter = 0;
  for (const list of bySource.values()) {
    const ids = new Set(list.filter((e) => ok(e.status)).map((e) => idRoute(e.path)?.id).filter(Boolean));
    answeredIds = Math.max(answeredIds, ids.size);
    let failures = 0;
    for (const e of [...list].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
      if (!isAuthPath(e.path) || (e.method && e.method.toUpperCase() !== "POST")) continue;
      if (e.status >= 400 && e.status < 500 && e.status !== 429) failures++;
      else if (e.status >= 200 && e.status < 400 && failures >= FAILURES_BEFORE_SIGN_IN) { signInAfter = Math.max(signInAfter, failures); break; }
    }
  }
  if (signInAfter > 0) {
    return { kind: "worked", detail: `A flagged source signed in after ${signInAfter} failed attempts. Check that account and reset its sessions.` };
  }
  if (answeredIds >= ANSWERED_IDS_THRESHOLD && hasIssue) {
    return { kind: "worked", detail: `Your app answered one flagged source with success on ${answeredIds} different record ids, on a route where the code has an open issue.` };
  }
  const errors = reported.filter((e) => e.status >= 500).length;
  if (errors > 0) {
    return { kind: "errored", detail: `Your app failed on ${errors} of these requests. An error on an attack request can mean the input reached a query; worth a look.` };
  }
  const answered = reported.filter((e) => ok(e.status) || (e.status >= 300 && e.status < 400)).length;
  if (answered === 0) return { kind: "refused", detail: `Every one of ${plural(reported.length, "reported answer", "reported answers")} refused the request.` };
  return { kind: "answered", detail: answeredIds >= ANSWERED_IDS_THRESHOLD
    ? `Answered with success on ${answeredIds} different record ids. Fine if these records are public; the code shows no issue here.`
    : `Answered ${answered} of ${plural(reported.length, "reported request", "reported requests")} with success.` };
}

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
  const routeHits = new Map<string, { pattern: string; file: string; requests: number; sources: Set<string>; events: EventRow[] }>();
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
      const hit = routeHits.get(route.file) ?? { ...route, requests: 0, sources: new Set<string>(), events: [] };
      hit.requests++; hit.sources.add(sourceId); hit.events.push(e);
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
      finding: f ? { title: f.title, severity: f.severity, confirmed: f.confirmed } : null,
      outcome: routeOutcome(r.events, Boolean(f)) };
  }).sort((a, b) => Number(b.outcome.kind === "worked") - Number(a.outcome.kind === "worked")
    || Number(Boolean(b.finding?.confirmed)) - Number(Boolean(a.finding?.confirmed))
    || Number(Boolean(b.finding)) - Number(Boolean(a.finding)) || b.requests - a.requests || a.pattern.localeCompare(b.pattern));

  const shown = attackers.slice(0, MAX_ATTACKERS);
  return {
    attackers: shown, attackedRoutes,
    totals: { attackers: attackers.length, blocked: attackers.filter((a) => a.status === "blocked").length,
      attackedRoutes: attackedRoutes.length, attackedWithIssue: attackedRoutes.filter((r) => r.finding).length,
      probablyWorked: attackedRoutes.filter((r) => r.outcome.kind === "worked").length, unmatchedPaths: unmatchedTotal },
  };
}

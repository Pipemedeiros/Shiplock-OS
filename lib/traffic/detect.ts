import type { Decision } from "@/lib/types";
import type { ProbeKind } from "./probe";
import { CRS_RESTRICTED_FILES, CRS_SCANNER_AGENTS } from "./crs/rules";

const PROBE_WORDS: Record<ProbeKind, string> = {
  sqli: "SQL injection", traversal: "path traversal", xss: "script injection",
  ssrf: "server-side request forgery", cmdi: "command injection", nosql: "NoSQL operator injection",
};

// Pure, deterministic traffic detection — no I/O, no Claude (same doctrine as
// lib/monitoring/findings.ts: background/hot-path logic must be cheap and
// testable). The ingest route fetches a source's recent events, this module
// turns them into signals and a Decision, and only the ingest route does DB
// writes. Kept pure so every threshold is unit-tested.
//
// Enforcement posture (owner decision): auto-block ONLY on high-confidence
// malicious signatures; softer anomalies alert but never block, so a real
// user never eats a false-positive 429.

// ── Tunable thresholds ─────────────────────────────────────────────────────
export const AUTH_WINDOW_MS = 60_000; // brute-force / credential-stuffing window
export const AUTH_ALERT_THRESHOLD = 10; // auth hits/window -> alert (no block)
export const AUTH_BLOCK_THRESHOLD = 20; // auth hits/window -> block (clear brute-force)

export const SCAN_WINDOW_MS = 300_000; // vuln-scanner path-probing window
export const SCAN_DISTINCT_THRESHOLD = 5; // distinct suspicious paths -> block

export const FLOOD_WINDOW_MS = 60_000; // raw request flood window
export const FLOOD_THRESHOLD = 100; // total hits/window from ONE source -> block

export const SESSION_WINDOW_MS = 600_000; // session-hijack window (10m)
export const SESSION_SOURCE_THRESHOLD = 4; // one session from >= N distinct sources -> alert

// P4: one source reading this many different record ids on one route inside
// SCAN_WINDOW_MS is walking ids (enumeration). Alert only: a person paging
// through their own records is possible, and blocking them would be wrong.
export const ID_WALK_THRESHOLD = 30;

export const BLOCK_TTL_LONG_MS = 60 * 60_000; // 1h — brute-force / scanner
export const BLOCK_TTL_SHORT_MS = 15 * 60_000; // 15m — flood

// Largest lookback the detector needs; the ingest layer fetches this window.
export const LOOKBACK_MS = Math.max(AUTH_WINDOW_MS, SCAN_WINDOW_MS, FLOOD_WINDOW_MS);
// Row cap on the fetch. Hitting it means >= this many requests from one source
// inside LOOKBACK_MS, which is itself flood-level — so a capped fetch is
// treated as a flood rather than silently under-counted.
export const FETCH_ROW_CAP = 300;

const NONE: Decision = { action: "none", reason: "", severity: "INFO", ttlMs: 0 };

// ── Path classifiers (pure, shared with tests) ─────────────────────────────
const AUTH_PATH_RE =
  /^\/(login|log-in|signin|sign-in|register|signup|sign-up|auth\b|session|token)|^\/api\/auth|\/auth\/|^\/api\/(?:[\w-]+\/)*(login|log-in|signin|sign-in|signup|sign-up|register)\/?$/i;

// Paths no legitimate app-of-this-kind serves — hitting several distinct ones
// is an automated vulnerability scanner, not a user.
const SUSPICIOUS_PATH_RES: RegExp[] = [
  /^\/\.env(\.|$|\/)/i,
  /^\/\.git(\/|$)/i,
  /^\/\.aws(\/|$)/i,
  /^\/\.ssh(\/|$)/i,
  /^\/\.DS_Store$/i,
  /^\/wp-admin(\/|$)/i,
  /^\/wp-login\.php/i,
  /^\/xmlrpc\.php/i,
  /^\/phpmyadmin(\/|$)/i,
  /^\/phpMyAdmin(\/|$)/,
  /^\/vendor\//i,
  /^\/\.git-credentials$/i,
  /^\/(backup|dump|db)\.sql$/i,
  /^\/(shell|c99|r57)\.php$/i,
];

export function isAuthPath(path: string): boolean {
  return AUTH_PATH_RE.test(path);
}

const RESTRICTED = CRS_RESTRICTED_FILES.map((s) => s.toLowerCase());
const AGENTS = CRS_SCANNER_AGENTS.map((s) => [s, s.toLowerCase()] as const);

/** A path no app of this kind serves: the rules above, or a CRS 930130 phrase anywhere in it. */
export function isSuspiciousPath(path: string): boolean {
  if (SUSPICIOUS_PATH_RES.some((re) => re.test(path))) return true;
  const p = path.split("?")[0].toLowerCase();
  return RESTRICTED.some((s) => p.includes(s));
}

/** The scanner a User-Agent names (CRS 913100), or null. Browsers and plain HTTP clients are not on the list. */
export function scannerAgent(ua: string | null | undefined): string | null {
  if (!ua) return null;
  const u = ua.toLowerCase();
  return AGENTS.find(([, lower]) => u.includes(lower))?.[0] ?? null;
}

const ID_SEGMENT = [
  /^\d+$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^[0-9a-f]{16,}$/i,
];
const isId = (seg: string) => ID_SEGMENT.some((re) => re.test(seg))
  || (/^[A-Za-z0-9_-]{16,}$/.test(seg) && /\d/.test(seg) && /[A-Za-z]/.test(seg));

/** A path with its record ids replaced by `:id`, and the ids it named; null
 * when no segment is an id. Words such as "new" or "settings" are not ids. */
export function idRoute(path: string): { pattern: string; id: string } | null {
  const segs = path.split("?")[0].split("/");
  const ids = segs.filter((seg) => seg && isId(seg));
  if (ids.length === 0) return null;
  return { pattern: segs.map((seg) => (seg && isId(seg) ? ":id" : seg)).join("/"), id: ids.join("/") };
}

// ── Signal extraction ──────────────────────────────────────────────────────
export interface EventRow {
  path: string;
  created_at: string; // ISO timestamp
}

export interface TrafficSignals {
  authCount: number; // auth-path hits within AUTH_WINDOW_MS
  distinctScanPaths: number; // distinct suspicious paths within SCAN_WINDOW_MS
  totalCount: number; // all hits within FLOOD_WINDOW_MS
  capped: boolean; // the source's fetch hit FETCH_ROW_CAP (flood-level on its own)
  // Distinct source_ids that presented THIS request's session within
  // SESSION_WINDOW_MS. Computed by a separate per-session query (not from this
  // source's rows), so it's passed in. 0 for anonymous requests.
  distinctSourcesForSession: number;
  // The route this source read the most different record ids on, inside
  // SCAN_WINDOW_MS (P4). Null when no path named an id.
  idWalk?: { pattern: string; distinct: number } | null;
  // The attack pattern the customer's snippet classified in THIS request
  // (lib/traffic/probe.ts); never the query itself.
  probe?: { kind: ProbeKind; path: string } | null;
  // A security scanner named in THIS request's User-Agent (CRS 913100).
  agent?: { name: string; path: string } | null;
}

// Pure: rows are this source's recent events (any order). `capped` says the
// upstream fetch was truncated at FETCH_ROW_CAP. `distinctSourcesForSession`
// comes from a separate per-session query in the ingest layer.
export function computeSignals(
  rows: EventRow[],
  nowMs: number,
  capped = false,
  distinctSourcesForSession = 0
): TrafficSignals {
  const authCutoff = nowMs - AUTH_WINDOW_MS;
  const floodCutoff = nowMs - FLOOD_WINDOW_MS;
  const scanCutoff = nowMs - SCAN_WINDOW_MS;

  let authCount = 0;
  let totalCount = 0;
  const scanPaths = new Set<string>();
  const idsByPattern = new Map<string, Set<string>>();

  for (const row of rows) {
    const ts = Date.parse(row.created_at);
    if (Number.isNaN(ts)) continue;
    if (ts >= floodCutoff) totalCount++;
    if (ts >= authCutoff && isAuthPath(row.path)) authCount++;
    if (ts >= scanCutoff && isSuspiciousPath(row.path)) scanPaths.add(row.path);
    const walked = ts >= scanCutoff ? idRoute(row.path) : null;
    if (walked) idsByPattern.set(walked.pattern, (idsByPattern.get(walked.pattern) ?? new Set()).add(walked.id));
  }

  let idWalk: TrafficSignals["idWalk"] = null;
  for (const [pattern, ids] of idsByPattern) {
    if (ids.size > 1 && (!idWalk || ids.size > idWalk.distinct)) idWalk = { pattern, distinct: ids.size };
  }
  return { authCount, distinctScanPaths: scanPaths.size, totalCount, capped, distinctSourcesForSession, idWalk };
}

// ── Decision (pure) ────────────────────────────────────────────────────────
// Most-specific / highest-confidence signatures first. Block rules always win
// over the alert rule.
export function detect(signals: TrafficSignals): Decision {
  if (signals.distinctScanPaths >= SCAN_DISTINCT_THRESHOLD) {
    return {
      action: "block",
      reason: `Vulnerability scanning: probed ${signals.distinctScanPaths} sensitive paths`,
      severity: "CRITICAL",
      ttlMs: BLOCK_TTL_LONG_MS,
    };
  }

  if (signals.authCount >= AUTH_BLOCK_THRESHOLD) {
    return {
      action: "block",
      reason: `Credential stuffing: ${signals.authCount} auth attempts in ${AUTH_WINDOW_MS / 1000}s`,
      severity: "CRITICAL",
      ttlMs: BLOCK_TTL_LONG_MS,
    };
  }

  if (signals.capped || signals.totalCount >= FLOOD_THRESHOLD) {
    const n = signals.capped ? `${FETCH_ROW_CAP}+` : `${signals.totalCount}`;
    return {
      action: "block",
      reason: `Request flood: ${n} requests in ${FLOOD_WINDOW_MS / 1000}s`,
      severity: "CRITICAL",
      ttlMs: BLOCK_TTL_SHORT_MS,
    };
  }

  // Session hijack: one session presented from many sources at once. ALERT
  // only — never auto-block, because blocking a valid session would lock out
  // the legitimate user, and distinguishing theft from a VPN/multi-device user
  // isn't certain enough to 429 on.
  if (signals.distinctSourcesForSession >= SESSION_SOURCE_THRESHOLD) {
    return {
      action: "alert",
      reason: `Possible session hijack: one session used from ${signals.distinctSourcesForSession} sources in ${SESSION_WINDOW_MS / 60000}m`,
      severity: "WARNING",
      ttlMs: 0,
    };
  }

  if (signals.probe) {
    return {
      action: "alert",
      reason: `Attack probe: ${PROBE_WORDS[signals.probe.kind]} pattern on ${signals.probe.path}`,
      severity: "WARNING",
      ttlMs: 0,
    };
  }

  // A scanner that names itself: alert only. Founders run nuclei or ZAP on
  // their own app, and blocking their own scan for an hour would be wrong.
  if (signals.agent) {
    return {
      action: "alert",
      reason: `Scanner tool: ${signals.agent.name} on ${signals.agent.path}`,
      severity: "WARNING",
      ttlMs: 0,
    };
  }

  if (signals.idWalk && signals.idWalk.distinct >= ID_WALK_THRESHOLD) {
    return {
      action: "alert",
      reason: `Walking record ids: ${signals.idWalk.distinct} different ids on ${signals.idWalk.pattern} in ${SCAN_WINDOW_MS / 60000} minutes`,
      severity: "WARNING",
      ttlMs: 0,
    };
  }

  if (signals.authCount >= AUTH_ALERT_THRESHOLD) {
    return {
      action: "alert",
      reason: `Elevated auth traffic: ${signals.authCount} attempts in ${AUTH_WINDOW_MS / 1000}s`,
      severity: "WARNING",
      ttlMs: 0,
    };
  }

  return NONE;
}

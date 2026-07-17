import type { RepoFile } from "./githubScan";

// PURE, no I/O. Builds a compact map of a repo's security-relevant surface for
// the reasoning pass (Layer 3). The deterministic tools + these heuristics do
// the *discovery*; the LLM only does *judgment* over this map — which is what
// keeps the reasoning pass cheap. Heuristic by design (regex, not full parse):
// it flags candidates for the LLM to reason about, never asserts on its own.

export interface Endpoint {
  path: string;
  methods: string[]; // exported HTTP handlers
  mutates: boolean; // writes to the DB / non-GET
  hasAuth: boolean; // references a session/auth check at all
  hasOwnershipScope: boolean; // scopes by user_id/owner/auth.uid()
  usesClientInputInWrite: boolean; // reads request body AND mutates (mass-assignment candidate)
}

export interface Rpc {
  name: string;
  file: string;
  securityDefiner: boolean;
  anonExecute: boolean; // GRANT EXECUTE ... TO anon/public
}

export interface ReasoningContext {
  endpoints: Endpoint[];
  rpcs: Rpc[];
  // True when the app has a middleware/proxy that makes auth decisions
  // (redirects/rewrites based on a session). If routes rely on it instead of
  // an in-handler check, they're bypassable — the CVE-2025-29927 class.
  middlewareAuthGate: boolean;
}

const ROUTE_RE = /(^|\/)(app\/.*\/route\.(ts|tsx|js|mjs)|pages\/api\/.*\.(ts|js))$/;
const HTTP_METHOD_RE = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
const MUTATION_RE = /\.(insert|update|delete|upsert)\s*\(/;
// Auth covers session auth AND the non-session forms real routes use: shared
// secrets, signature verification, and unguessable path/header tokens — so a
// signature-verified webhook isn't mislabeled "no auth".
const AUTH_RE =
  /auth\.uid\(\)|getUser\s*\(|getSession\s*\(|requireProUser|\.auth\.getUser|supabase\.auth|CRON_SECRET|constructEvent|webhooks?\.|x-site|_token\b|headers?\.get\(\s*["']authorization|Bearer /i;
// Ownership includes writes scoped by a SERVER-DERIVED id (userId/user.id/
// pro.userId), not just the literal "user_id" — that's still ownership-safe.
const OWNERSHIP_RE =
  /owner_id|auth\.uid\(\)|\.eq\(\s*["'](user_id|id)["']\s*,\s*(userId|user\.id|pro\.userId|session)|\buser_id\b/;
const CLIENT_INPUT_RE = /\.json\(\)|\bbody\b|req\.body|params\b/;
const TRIGGER_RE = /returns\s+trigger/i;

const MAX_ENDPOINTS = 80;
const MAX_RPCS = 60;

export function isRouteFile(path: string): boolean {
  return ROUTE_RE.test(path);
}

export function extractEndpoints(files: RepoFile[]): Endpoint[] {
  const out: Endpoint[] = [];
  for (const f of files) {
    if (!isRouteFile(f.path)) continue;
    const methods = [...new Set([...f.content.matchAll(HTTP_METHOD_RE)].map((m) => m[1]))];
    const mutates = MUTATION_RE.test(f.content) || methods.some((m) => m !== "GET");
    const hasAuth = AUTH_RE.test(f.content);
    const hasOwnershipScope = OWNERSHIP_RE.test(f.content);
    const usesClientInputInWrite = mutates && CLIENT_INPUT_RE.test(f.content);
    out.push({ path: f.path, methods, mutates, hasAuth, hasOwnershipScope, usesClientInputInWrite });
  }
  return out.slice(0, MAX_ENDPOINTS);
}

// Extract Postgres functions from .sql migrations, flagging SECURITY DEFINER and
// whether they're anon-callable — Strix's highest-value Supabase targets (a
// SECURITY DEFINER function callable by anon bypasses RLS as its owner).
// CRITICAL nuance: Postgres grants EXECUTE to PUBLIC (anon) BY DEFAULT, so a
// function is anon-callable UNLESS explicitly REVOKEd. Trigger functions aren't
// RPC-callable, so they're excluded.
export function extractRpcs(files: RepoFile[]): Rpc[] {
  const byName = new Map<string, Rpc>();
  const isTrigger = new Set<string>();
  const revokedFromAnon = new Set<string>();
  const get = (name: string, file: string): Rpc => {
    const existing = byName.get(name);
    if (existing) return existing;
    const rpc: Rpc = { name, file, securityDefiner: false, anonExecute: false };
    byName.set(name, rpc);
    return rpc;
  };

  for (const f of files) {
    if (!/\.sql$/i.test(f.path)) continue;
    for (const stmt of f.content.split(";")) {
      const create = /create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?([a-z0-9_]+)/i.exec(stmt);
      if (create) {
        const name = create[1].toLowerCase();
        const rpc = get(name, f.path);
        if (/security\s+definer/i.test(stmt)) rpc.securityDefiner = true;
        if (TRIGGER_RE.test(stmt)) isTrigger.add(name);
      }
      const revoke = /revoke\s+execute\s+on\s+function\s+(?:public\.)?([a-z0-9_]+)/i.exec(stmt);
      if (revoke && /from\s+(anon|public)\b/i.test(stmt)) revokedFromAnon.add(revoke[1].toLowerCase());
    }
  }

  // Anon-callable by Postgres default unless it's a trigger or explicitly revoked.
  for (const [name, rpc] of byName) {
    rpc.anonExecute = !isTrigger.has(name) && !revokedFromAnon.has(name);
  }
  return [...byName.values()].slice(0, MAX_RPCS);
}

const MIDDLEWARE_FILE_RE = /(^|\/)(middleware|proxy)\.(ts|js|mjs)$/;
const MW_SESSION_RE = /getUser|auth\.uid|getSession|isAuthenticated|\.auth\b|session/i;
const MW_DECISION_RE = /redirect|rewrite|NextResponse\.(redirect|rewrite)/i;

// Does the app gate access in middleware (session-based redirect/rewrite)? If so
// and routes lack their own in-handler check, they're bypassable (CVE-2025-29927:
// a crafted request can skip Next.js middleware). This is a cheap, named-CVE win.
export function detectMiddlewareAuthGate(files: RepoFile[]): boolean {
  return files.some(
    (f) => MIDDLEWARE_FILE_RE.test(f.path) && MW_SESSION_RE.test(f.content) && MW_DECISION_RE.test(f.content)
  );
}

export function buildReasoningContext(files: RepoFile[]): ReasoningContext {
  return {
    endpoints: extractEndpoints(files),
    rpcs: extractRpcs(files),
    middlewareAuthGate: detectMiddlewareAuthGate(files),
  };
}

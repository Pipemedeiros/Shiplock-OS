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
}

const ROUTE_RE = /(^|\/)(app\/.*\/route\.(ts|tsx|js|mjs)|pages\/api\/.*\.(ts|js))$/;
const HTTP_METHOD_RE = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
const MUTATION_RE = /\.(insert|update|delete|upsert)\s*\(/;
const AUTH_RE = /auth\.uid\(\)|getUser\s*\(|getSession\s*\(|requireProUser|\.auth\.getUser|supabase\.auth/;
const OWNERSHIP_RE = /user_id|owner_id|auth\.uid\(\)|\.eq\(\s*["']user_id["']/;
const CLIENT_INPUT_RE = /\.json\(\)|\bbody\b|req\.body|params\b/;

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
// anon/public EXECUTE grants — Strix's highest-value Supabase targets (a
// SECURITY DEFINER function callable by anon bypasses RLS as its owner).
export function extractRpcs(files: RepoFile[]): Rpc[] {
  const byName = new Map<string, Rpc>();
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
        const rpc = get(create[1].toLowerCase(), f.path);
        if (/security\s+definer/i.test(stmt)) rpc.securityDefiner = true;
      }
      const grant = /grant\s+execute\s+on\s+function\s+(?:public\.)?([a-z0-9_]+)/i.exec(stmt);
      if (grant && /to\s+(anon|public)\b/i.test(stmt)) {
        get(grant[1].toLowerCase(), f.path).anonExecute = true;
      }
    }
  }
  return [...byName.values()].slice(0, MAX_RPCS);
}

export function buildReasoningContext(files: RepoFile[]): ReasoningContext {
  return { endpoints: extractEndpoints(files), rpcs: extractRpcs(files) };
}

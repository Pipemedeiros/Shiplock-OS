// Supabase Management API client — READ-ONLY, by construction.
//
// Why this exists: lib/deep/policyScan.ts can detect permissive RLS policies
// (`USING (true)` on a client-reachable role — the most common real Supabase
// critical), but an external anon-key scan can't see policy definitions. Only
// the Management API can. This module is the connection.
//
// THE BOUNDARY. The Management API's query endpoint executes arbitrary SQL,
// including writes. ShipLock never writes a customer's production database
// (CLAUDE.md, non-negotiable), so `runReadQuery` refuses to send anything that
// isn't a single read statement. That guard is defence-in-depth, not the only
// control — we also simply never call it with anything else — but a guard that
// lives next to the transport is the one that survives a future refactor.

import { decrypt } from "@/lib/crypto";
import type { PgPolicy, SupabaseAdvisor } from "./policyScan";
import { GRANT_INVENTORY_SQL } from "./grantScan";

const API = "https://api.supabase.com";
const AUTHORIZE_URL = `${API}/v1/oauth/authorize`;
const TOKEN_URL = `${API}/v1/oauth/token`;

export interface MgmtToken {
  accessToken: string;
  refreshToken: string | null;
  /** Absolute expiry, ISO. */
  expiresAt: string | null;
}

export function isSupabaseMgmtConfigured(): boolean {
  return Boolean(process.env.SUPABASE_OAUTH_CLIENT_ID && process.env.SUPABASE_OAUTH_CLIENT_SECRET);
}

/** Where we send the customer to authorise the connection. */
export function authorizeUrl(state: string, appUrl: string): string {
  const params = new URLSearchParams({
    client_id: process.env.SUPABASE_OAUTH_CLIENT_ID ?? "",
    redirect_uri: `${appUrl.replace(/\/+$/, "")}/api/deep/supabase/callback`,
    response_type: "code",
    state,
  });
  return `${AUTHORIZE_URL}?${params.toString()}`;
}

function basicAuthHeader(): string {
  const raw = `${process.env.SUPABASE_OAUTH_CLIENT_ID}:${process.env.SUPABASE_OAUTH_CLIENT_SECRET}`;
  return `Basic ${Buffer.from(raw).toString("base64")}`;
}

function toToken(json: {
  access_token: string;
  refresh_token?: string | null;
  expires_in?: number | null;
}): MgmtToken {
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token ?? null,
    expiresAt: json.expires_in ? new Date(Date.now() + json.expires_in * 1000).toISOString() : null,
  };
}

export async function exchangeCodeForToken(code: string, appUrl: string): Promise<MgmtToken> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      authorization: basicAuthHeader(),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${appUrl.replace(/\/+$/, "")}/api/deep/supabase/callback`,
    }),
  });
  if (!res.ok) throw new Error(`Supabase token exchange HTTP ${res.status}`);
  return toToken(await res.json());
}

export async function refreshAccessToken(refreshToken: string): Promise<MgmtToken> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      authorization: basicAuthHeader(),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
  });
  if (!res.ok) throw new Error(`Supabase token refresh HTTP ${res.status}`);
  return toToken(await res.json());
}

/**
 * Returns a usable access token, refreshing first if the stored one is expired
 * or within five minutes of it. Returns null when there's nothing usable.
 */
export async function getUsableToken(row: {
  supabase_mgmt_token_encrypted: string | null;
  supabase_mgmt_refresh_encrypted: string | null;
  supabase_mgmt_expires_at: string | null;
}): Promise<{ token: MgmtToken; refreshed: boolean } | null> {
  if (!row.supabase_mgmt_token_encrypted) return null;

  const expiresAt = row.supabase_mgmt_expires_at ? Date.parse(row.supabase_mgmt_expires_at) : null;
  const stale = expiresAt !== null && expiresAt - Date.now() < 5 * 60 * 1000;

  if (!stale) {
    return {
      token: {
        accessToken: decrypt(row.supabase_mgmt_token_encrypted),
        refreshToken: row.supabase_mgmt_refresh_encrypted
          ? decrypt(row.supabase_mgmt_refresh_encrypted)
          : null,
        expiresAt: row.supabase_mgmt_expires_at,
      },
      refreshed: false,
    };
  }

  if (!row.supabase_mgmt_refresh_encrypted) return null;
  const token = await refreshAccessToken(decrypt(row.supabase_mgmt_refresh_encrypted));
  return { token, refreshed: true };
}

// ── The read-only guard ──────────────────────────────────────────────────
// Anything that isn't a single SELECT/WITH…SELECT is refused before it can
// reach the customer's database. Blocks stacked statements outright, since one
// semicolon is all it takes to append a write to an innocent-looking read.

const WRITE_KEYWORDS =
  /\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|comment|copy|call|do|vacuum|reindex|refresh|set|reset|begin|commit|rollback|security\s+label)\b/i;

export function assertReadOnly(sql: string): void {
  const trimmed = sql.trim().replace(/;+\s*$/, "");

  if (trimmed.includes(";")) {
    throw new Error("Refusing multi-statement SQL on a customer database.");
  }
  if (!/^\s*(select|with)\b/i.test(trimmed)) {
    throw new Error("Refusing non-SELECT SQL on a customer database.");
  }
  if (WRITE_KEYWORDS.test(trimmed)) {
    throw new Error("Refusing SQL containing a write keyword on a customer database.");
  }
}

async function runReadQuery<T>(accessToken: string, projectRef: string, sql: string): Promise<T[]> {
  assertReadOnly(sql);

  const res = await fetch(`${API}/v1/projects/${encodeURIComponent(projectRef)}/database/query`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ query: sql, read_only: true }),
  });
  if (!res.ok) throw new Error(`Supabase query HTTP ${res.status}`);
  const json = await res.json();
  return Array.isArray(json) ? (json as T[]) : [];
}

export interface MgmtProject {
  id: string;
  ref: string;
  name: string;
}

export async function listProjects(accessToken: string): Promise<MgmtProject[]> {
  const res = await fetch(`${API}/v1/projects`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Supabase list-projects HTTP ${res.status}`);
  const json = (await res.json()) as { id: string; ref?: string; name: string }[];
  return (json ?? []).map((p) => ({ id: p.id, ref: p.ref ?? p.id, name: p.name }));
}

/** Every RLS policy on the public schema — the input policyScan.ts wants. */
export async function fetchPolicies(accessToken: string, projectRef: string): Promise<PgPolicy[]> {
  const rows = await runReadQuery<{
    schemaname: string;
    tablename: string;
    policyname: string;
    cmd: string;
    qual: string | null;
    with_check: string | null;
    roles: string[] | string | null;
  }>(
    accessToken,
    projectRef,
    `SELECT schemaname, tablename, policyname, cmd, qual, with_check, roles
       FROM pg_policies
      WHERE schemaname = 'public'`
  );

  return rows.map((r) => ({
    schemaname: r.schemaname,
    tablename: r.tablename,
    policyname: r.policyname,
    cmd: r.cmd,
    qual: r.qual,
    with_check: r.with_check,
    // pg returns roles as a name[]; some transports stringify it as "{a,b}".
    roles: Array.isArray(r.roles)
      ? r.roles
      : typeof r.roles === "string"
        ? r.roles.replace(/^\{|\}$/g, "").split(",").filter(Boolean)
        : [],
  }));
}

/** Supabase's own security advisors. Best-effort — shape varies by version. */
export async function fetchAdvisors(
  accessToken: string,
  projectRef: string
): Promise<SupabaseAdvisor[]> {
  try {
    const res = await fetch(
      `${API}/v1/projects/${encodeURIComponent(projectRef)}/advisors/security`,
      { headers: { authorization: `Bearer ${accessToken}` } }
    );
    if (!res.ok) return [];
    const json = await res.json();
    const list = Array.isArray(json) ? json : (json?.lints ?? json?.advisors ?? []);
    return Array.isArray(list) ? (list as SupabaseAdvisor[]) : [];
  } catch {
    return [];
  }
}

/**
 * The project's auth configuration (URL configuration, session and signup
 * settings). Read-only GET — it does not go through the SQL query endpoint, so
 * assertReadOnly does not apply and cannot: there is no SQL here to guard.
 *
 * Best-effort and untyped beyond the fields we read, because Supabase adds keys
 * to this endpoint over time and a strict shape would start failing on its own.
 */
export interface SupabaseAuthConfig {
  /** Default redirect target for email confirmations and password resets. */
  site_url?: string | null;
  /** Comma-separated additional redirect allow-list, glob patterns permitted. */
  uri_allow_list?: string | null;
  [key: string]: unknown;
}

export async function fetchAuthConfig(
  accessToken: string,
  projectRef: string
): Promise<SupabaseAuthConfig | null> {
  try {
    const res = await fetch(`${API}/v1/projects/${encodeURIComponent(projectRef)}/config/auth`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) return null;
    const json = await res.json();
    return json && typeof json === "object" ? (json as SupabaseAuthConfig) : null;
  } catch {
    return null;
  }
}

// ── Schema inventory for the exposure model (A21) ──────────────────────────
//
// SCHEMA ONLY. These two queries return column NAMES and row COUNTS. They never
// select a column's contents, and they must never be extended to — "ShipLock
// never reads your users' data" is a customer-facing promise, and this is the
// exact place it would be broken for a marginal accuracy gain.

export interface SchemaColumn {
  table: string;
  column: string;
}

export async function fetchSchemaColumns(
  accessToken: string,
  projectRef: string
): Promise<SchemaColumn[]> {
  const rows = await runReadQuery<{ table_name: string; column_name: string }>(
    accessToken,
    projectRef,
    `select table_name, column_name from information_schema.columns
     where table_schema = 'public'
     order by table_name, ordinal_position`
  );
  return rows.map((r) => ({ table: r.table_name, column: r.column_name }));
}

/** Postgres identifier quoting, so an odd table name cannot break out. */
export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/**
 * Builds one UNION ALL statement counting every named table.
 *
 * EXACT counts, deliberately. pg_stat_user_tables.n_live_tup would be cheaper
 * but it is a statistics ESTIMATE, and §13.5 guardrail 6 forbids estimated row
 * counts in the exposure model — a plausible-looking number built on a guess is
 * exactly the failure this feature cannot afford.
 *
 * Exported for tests: the escaping and the single-statement shape are what keep
 * this inside assertReadOnly's guarantees.
 */
export function buildRowCountSql(tables: string[]): string | null {
  const safe = tables.filter((t) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(t));
  if (safe.length === 0) return null;
  return safe
    .map((t) => `select '${t}' as table_name, count(*)::bigint as n from public.${quoteIdent(t)}`)
    .join(" union all ");
}

export async function fetchRowCounts(
  accessToken: string,
  projectRef: string,
  tables: string[]
): Promise<Map<string, number>> {
  const sql = buildRowCountSql(tables);
  if (!sql) return new Map();
  try {
    const rows = await runReadQuery<{ table_name: string; n: number | string }>(
      accessToken,
      projectRef,
      sql
    );
    const out = new Map<string, number>();
    for (const r of rows) {
      const n = typeof r.n === "string" ? Number.parseInt(r.n, 10) : r.n;
      if (Number.isFinite(n)) out.set(r.table_name, n);
    }
    return out;
  } catch {
    // Counting can fail on a large or busy database. An absent count means the
    // exposure model reports no number for that table, which is correct.
    return new Map();
  }
}

// ── Auth audit log (E5-E7) ─────────────────────────────────────────────────
//
// Supabase's log endpoint is EXPERIMENTAL: the path, the query shape and the
// field names have all moved between versions, and we cannot verify this against
// a live project until a customer connects one. So it is written to fail into
// silence rather than into a wrong answer — an unrecognised response yields no
// events, which yields no findings, which is the correct behaviour for "we could
// not look". lib/runtime/authEvents.ts normalises whatever shape does come back.
//
// The alternative — inventing findings from a response we half-understood — is
// the failure this codebase has produced repeatedly and is explicitly guarded
// against here.

const AUTH_LOG_HOURS = 24; // the endpoint's documented maximum range

export async function fetchAuthAuditLog(
  accessToken: string,
  projectRef: string
): Promise<Record<string, unknown>[]> {
  const iso = (d: Date) => d.toISOString();
  const end = new Date();
  const start = new Date(end.getTime() - AUTH_LOG_HOURS * 60 * 60 * 1000);

  const url =
    `${API}/v1/projects/${encodeURIComponent(projectRef)}/analytics/endpoints/logs.all` +
    `?iso_timestamp_start=${encodeURIComponent(iso(start))}` +
    `&iso_timestamp_end=${encodeURIComponent(iso(end))}` +
    `&sql=${encodeURIComponent(
      "select id, timestamp, event_message, metadata from auth_logs order by timestamp desc limit 1000"
    )}`;

  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return [];
    const json = await res.json();
    const rows = Array.isArray(json) ? json : (json?.result ?? json?.data ?? []);
    return Array.isArray(rows) ? (rows as Record<string, unknown>[]) : [];
  } catch {
    return [];
  }
}

/** A5 — column grants held by the roles a browser can reach. */
export async function fetchColumnGrants(
  accessToken: string,
  projectRef: string
): Promise<{ grantee: string; table: string; column: string; privilege: string }[]> {
  try {
    const rows = await runReadQuery<{
      grantee: string;
      table_name: string;
      column_name: string;
      privilege_type: string;
    }>(accessToken, projectRef, GRANT_INVENTORY_SQL);
    return rows.map((r) => ({
      grantee: r.grantee,
      table: r.table_name,
      column: r.column_name,
      privilege: r.privilege_type,
    }));
  } catch {
    // Unknown is not a finding.
    return [];
  }
}

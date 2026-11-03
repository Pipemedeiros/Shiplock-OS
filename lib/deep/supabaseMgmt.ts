// Supabase Management API client — READ-ONLY, by construction.
//
// Why this exists: lib/deep/policyScan.ts can detect permissive RLS policies
// (`USING (true)` on a client-reachable role — the most common real Supabase
// critical), but an external anon-key scan can't see policy definitions. Only
// the Management API can. This module is the connection.
//
// THE BOUNDARY. The Management API's query endpoint executes arbitrary SQL,
// including writes. ShipLock never writes a customer's production database
// (AGENTS.md, non-negotiable), so `runReadQuery` refuses to send anything that
// isn't a single read statement. That guard is defence-in-depth, not the only
// control — we also simply never call it with anything else — but a guard that
// lives next to the transport is the one that survives a future refactor.

import { z } from "zod";
import { ALL_SCHEMA_COLUMNS_SQL, type SchemaColumn } from "./schemaColumns";
import { decrypt } from "@/lib/crypto";
import { requestSignal } from "@/lib/abort";
import {
  ColumnGrantRow,
  parseObject,
  parseRows,
  PgPolicyRow,
  RowCountRow,
  SchemaColumnRow,
  SupabaseAdvisorRow,
  SupabaseAuthConfigObject,
  ExtensionRow,
  NetworkGrantRow,
  CronJobRow,
  ForeignServerRow,
  BucketRowSchema,
  StoragePolicyRowSchema,
  RealtimeTableRowSchema,
  AuthHookRowSchema,
} from "./apiSchemas";
import type { PgPolicy, SupabaseAdvisor } from "./policyScan";
import { GRANT_INVENTORY_SQL } from "./grantScan";
import { EXTENSION_SQL, NETWORK_GRANT_SQL, CRON_JOB_SQL, FDW_SQL } from "./extensionScan";
import { BUCKET_SQL, STORAGE_POLICY_SQL, type BucketRow, type StoragePolicyRow } from "./storageScan";
import { REALTIME_SQL, AUTH_HOOK_SQL, type RealtimeTableRow, type AuthHookRow } from "./realtimeScan";

const API = "https://api.supabase.com";
const AUTHORIZE_URL = `${API}/v1/oauth/authorize`;
const TOKEN_URL = `${API}/v1/oauth/token`;

export interface MgmtToken {
  accessToken: string;
  refreshToken: string | null;
  /** Absolute expiry, ISO. */
  expiresAt: string | null;
}

/** Whether the Supabase OAuth app is configured; without it the connection is
 * hidden. */
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

/** Exchanges an OAuth code for Supabase Management API tokens. */
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

/** Throws unless the SQL is a single SELECT or WITH statement. Every query on a
 * customer database passes through it. */
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

/**
 * Run a read query and VALIDATE the rows it returns.
 *
 * The `schema` parameter is not optional, and the previous signature —
 * `runReadQuery<T>(...)` returning `json as T[]` — is why. A cast is a promise
 * to the compiler that evaporates at runtime, so a renamed column arrived as
 * `undefined`, every downstream predicate read false, and the customer saw a
 * clean scan of a leaking database. `source` names the caller so a failure says
 * which layer stopped being trustworthy.
 */
async function runReadQuery<T>(
  accessToken: string,
  projectRef: string,
  sql: string,
  source: string,
  schema: z.ZodType<T>,
  signal?: AbortSignal,
): Promise<T[]> {
  assertReadOnly(sql);

  const res = await fetch(`${API}/v1/projects/${encodeURIComponent(projectRef)}/database/query`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ query: sql, read_only: true }),
    signal,
  });
  if (!res.ok) throw new Error(`Supabase query HTTP ${res.status}`);
  return parseRows(source, schema, await res.json());
}

export interface MgmtProject {
  id: string;
  ref: string;
  name: string;
}

/** The Supabase projects the token can see. */
export async function listProjects(accessToken: string): Promise<MgmtProject[]> {
  const res = await fetch(`${API}/v1/projects`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Supabase list-projects HTTP ${res.status}`);
  const json = (await res.json()) as { id: string; ref?: string; name: string }[];
  return (json ?? []).map((p) => ({ id: p.id, ref: p.ref ?? p.id, name: p.name }));
}

/** Every RLS policy on the public schema — the input policyScan.ts wants. */
export async function fetchPolicies(
  accessToken: string, projectRef: string, signal?: AbortSignal,
): Promise<PgPolicy[]> {
  // The schema normalises `roles` (array or "{a,b}" string) via PgRoleArray, so
  // the hand-rolled branch that used to live here is gone — one place to be
  // wrong instead of two, since the direct-Postgres transport reads the same
  // column.
  return runReadQuery(
    accessToken,
    projectRef,
    `SELECT schemaname, tablename, policyname, cmd, qual, with_check, roles
       FROM pg_policies
      WHERE schemaname = 'public'`,
    "fetchPolicies",
    PgPolicyRow,
    signal,
  );
}

/**
 * Supabase's own security advisors — a SECOND, independent source for facts the
 * policy scan already establishes.
 *
 * Two different failures are separated here, because they deserve opposite
 * treatment and the old `catch { return [] }` collapsed them:
 *
 *  - The endpoint is unavailable (network, 4xx/5xx, not enabled on this
 *    project). Genuinely best-effort: advisors corroborate, they are not the
 *    only witness, and a project without them is a normal state. Returns [].
 *  - The endpoint answered with something that is not an advisor list. That is
 *    a contract change, and swallowing it means quietly losing a corroborating
 *    source without anyone noticing for months. Throws, and the caller decides
 *    whether to degrade or fail — see runPolicyScan.
 *
 * The schema is permissive on purpose (every field optional), because this
 * payload really does vary by Supabase version. A parse failure therefore means
 * the response stopped being a list of lint-shaped objects at all, not that a
 * cosmetic field moved.
 */
export async function fetchAdvisors(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<SupabaseAdvisor[]> {
  let json: unknown;
  try {
    const res = await fetch(
      `${API}/v1/projects/${encodeURIComponent(projectRef)}/advisors/security`,
      { headers: { authorization: `Bearer ${accessToken}` }, signal }
    );
    if (!res.ok) return [];
    json = await res.json();
  } catch {
    return [];
  }

  // The list has lived under three keys across versions; all three are the
  // documented shape, so none of them is a mismatch.
  const list = Array.isArray(json)
    ? json
    : ((json as { lints?: unknown; advisors?: unknown })?.lints ??
      (json as { advisors?: unknown })?.advisors ??
      []);

  return parseRows("fetchAdvisors", SupabaseAdvisorRow, list);
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

/** The project's auth configuration, or null when unreadable. */
export async function fetchAuthConfig(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<SupabaseAuthConfig | null> {
  try {
    const res = await fetch(`${API}/v1/projects/${encodeURIComponent(projectRef)}/config/auth`, {
      headers: { authorization: `Bearer ${accessToken}` },
      signal,
    });
    if (!res.ok) return null;
    const json = await res.json();
    // `typeof [] === "object"`, so the old check accepted an array and handed
    // the auth scanners something with no keys — which reads as "every setting
    // absent", i.e. a clean config. parseObject rejects it.
    //
    // Returning null on failure is correct here and is NOT the silent-failure
    // pattern: readAuthPosture(null) yields signupsOpen/autoConfirm = null,
    // which the reasoner treats as unknown and never as safe. Absence of this
    // config removes an amplifier from a finding; it cannot remove a finding.
    return parseObject("fetchAuthConfig", SupabaseAuthConfigObject, json) as SupabaseAuthConfig;
  } catch {
    return null;
  }
}

// ── Schema inventory for the exposure model ──────────────────────────
//
// SCHEMA ONLY. These two queries return column NAMES and row COUNTS. They never
// select a column's contents, and they must never be extended to — "ShipLock
// never reads your users' data" is a customer-facing promise, and this is the
// exact place it would be broken for a marginal accuracy gain.

export type { SchemaColumn } from "./schemaColumns";

/** Every public table's column names and types; never values. */
export async function fetchSchemaColumns(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<SchemaColumn[]> {
  const rows = await runReadQuery(
    accessToken,
    projectRef,
    ALL_SCHEMA_COLUMNS_SQL,
    "fetchSchemaColumns",
    SchemaColumnRow,
    signal,
  );
  // Every column, for the exposure inventory; the bounded snapshot copy is
  // derived by the caller (schemaColumns.boundedSchemaColumns).
  return rows.map((r) => ({ table: r.table_name, column: r.column_name, type: r.data_type }));
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

/** Row counts for the given tables; counts only, never rows. */
export async function fetchRowCounts(
  accessToken: string,
  projectRef: string,
  tables: string[],
  signal?: AbortSignal,
): Promise<Map<string, number>> {
  const sql = buildRowCountSql(tables);
  if (!sql) return new Map();
  try {
    const rows = await runReadQuery(accessToken, projectRef, sql, "fetchRowCounts", RowCountRow, signal);
    const out = new Map<string, number>();
    // PgCount already coerced the bigint-as-string case and dropped non-finite
    // values, so this is a plain copy rather than a second parsing attempt.
    for (const r of rows) out.set(r.table_name, r.n);
    return out;
  } catch {
    // Counting can fail on a large or busy database. An absent count means the
    // exposure model reports no number for that table, which is correct.
    return new Map();
  }
}

// ── Auth audit log ─────────────────────────────────────────────────
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

/** Recent auth audit log events for runtime detection. */
export async function fetchAuthAuditLog(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
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
      signal: requestSignal(signal, 15_000),
    });
    if (!res.ok) return [];
    const json = await res.json();
    const rows = Array.isArray(json) ? json : (json?.result ?? json?.data ?? []);
    return Array.isArray(rows) ? (rows as Record<string, unknown>[]) : [];
  } catch {
    return [];
  }
}

// ── API gateway request log ─────────────────────────────────────────
//
// Supabase's documented Management API log query (Debugging projects:
// GET /v1/projects/{ref}/analytics/endpoints/logs.all) over `edge_logs`, the
// gateway in front of the REST, auth and storage APIs. Read-only. Only the
// fields needed to judge a client are selected; the IP is hashed by the caller
// on arrival and never stored. Field names were confirmed on ShipLock's own
// project (request.path, request.method, response.status_code, client IP); a
// customer project's response is validated row by row and an unrecognized
// shape reads as "unread", never as quiet.
const EDGE_LOG_HOURS = 6;

/** Recent API gateway requests (method, path, status), with ok false when the
 * log could not be read. */
export async function fetchEdgeRequestLog(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{ ok: boolean; rows: Record<string, unknown>[] }> {
  const end = new Date();
  const start = new Date(end.getTime() - EDGE_LOG_HOURS * 60 * 60 * 1000);
  const sql = [
    "select cast(timestamp as string) as ts, request.method as method, request.path as path,",
    "response.status_code as status, headers.cf_connecting_ip as ip",
    "from edge_logs cross join unnest(metadata) as metadata",
    "cross join unnest(metadata.request) as request cross join unnest(metadata.response) as response",
    "cross join unnest(request.headers) as headers",
    "order by timestamp desc limit 5000",
  ].join(" ");
  const url =
    `${API}/v1/projects/${encodeURIComponent(projectRef)}/analytics/endpoints/logs.all` +
    `?iso_timestamp_start=${encodeURIComponent(start.toISOString())}` +
    `&iso_timestamp_end=${encodeURIComponent(end.toISOString())}` +
    `&sql=${encodeURIComponent(sql)}`;
  try {
    const res = await fetch(url, { headers: { authorization: `Bearer ${accessToken}` }, signal: requestSignal(signal, 15_000) });
    if (!res.ok) return { ok: false, rows: [] };
    const json = await res.json();
    if (json && typeof json === "object" && "error" in json && json.error) return { ok: false, rows: [] };
    const rows = Array.isArray(json) ? json : (json?.result ?? json?.data);
    return Array.isArray(rows) ? { ok: true, rows: rows as Record<string, unknown>[] } : { ok: false, rows: [] };
  } catch {
    return { ok: false, rows: [] };
  }
}

/** Column grants held by the roles a browser can reach. */
export async function fetchColumnGrants(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{ grantee: string; table: string; column: string; privilege: string }[] | null> {
  try {
    const rows = await runReadQuery(
      accessToken,
      projectRef,
      GRANT_INVENTORY_SQL,
      "fetchColumnGrants",
      ColumnGrantRow,
      signal,
    );
    return rows.map((r) => ({
      grantee: r.grantee,
      table: r.table_name,
      column: r.column_name,
      privilege: r.privilege_type,
    }));
  } catch {
    // Unknown is not a finding, and not "no grants": null keeps the family unread.
    return null;
  }
}

/**
 * What the database can reach.
 *
 * Each query is independent and best-effort: cron.job does not exist unless
 * pg_cron is installed, and a failure there must not cost us the others. A
 * missing result is left UNDEFINED rather than empty, so the analyzer can tell
 * "we looked and found none" apart from "we could not look".
 */
export async function fetchDatabaseCapabilities(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{
  extensions?: { name: string; schema: string }[];
  networkGrants?: { schema: string; name: string; grantee: string }[];
  cronJobs?: { name: string | null; schedule: string; runs_as: string; command: string }[];
  foreignServers?: { server: string; wrapper: string }[];
}> {
  // `undefined` on failure, never `[]` — the caller distinguishes "we could not
  // look" from "we looked and there was nothing", and collapsing them would make
  // an unreadable capability list read as a clean one.
  const attempt = async <T>(sql: string, source: string, schema: z.ZodType<T>) => {
    try {
      return await runReadQuery(accessToken, projectRef, sql, source, schema, signal);
    } catch {
      return undefined;
    }
  };

  const [extensions, networkGrants, cronJobs, foreignServers] = await Promise.all([
    attempt(EXTENSION_SQL, "fetchExtensions", ExtensionRow),
    attempt(NETWORK_GRANT_SQL, "fetchNetworkGrants", NetworkGrantRow),
    attempt(CRON_JOB_SQL, "fetchCronJobs", CronJobRow),
    attempt(FDW_SQL, "fetchForeignServers", ForeignServerRow),
  ]);

  return { extensions, networkGrants, cronJobs, foreignServers };
}

/** Storage buckets and the policies governing their objects. */
export async function fetchStorageConfig(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{ buckets?: BucketRow[]; policies?: StoragePolicyRow[] }> {
  // `undefined` on failure, never `[]` — the caller distinguishes "we could not
  // look" from "we looked and there was nothing", and collapsing them would make
  // an unreadable capability list read as a clean one.
  const attempt = async <T>(sql: string, source: string, schema: z.ZodType<T>) => {
    try {
      return await runReadQuery(accessToken, projectRef, sql, source, schema, signal);
    } catch {
      return undefined;
    }
  };
  const [buckets, policies] = await Promise.all([
    attempt(BUCKET_SQL, "fetchBuckets", BucketRowSchema),
    attempt(STORAGE_POLICY_SQL, "fetchStoragePolicies", StoragePolicyRowSchema),
  ]);
  return { buckets, policies };
}

/**
 * Point-in-time recovery.
 *
 * Read-only GET. Returns null when the endpoint is unavailable, which includes
 * the very common case of a plan that does not offer PITR — and "not available
 * on your plan" is not a security finding, so the analyzer treats null as
 * "we could not look" rather than "backups are missing".
 */
export async function fetchBackupConfig(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{ pitrEnabled: boolean; walgEnabled: boolean } | null> {
  try {
    const res = await fetch(`${API}/v1/projects/${encodeURIComponent(projectRef)}/database/backups`, {
      headers: { authorization: `Bearer ${accessToken}` },
      signal: requestSignal(signal, 15_000),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as { pitr_enabled?: unknown; walg_enabled?: unknown };
    if (typeof json.pitr_enabled !== "boolean" && typeof json.walg_enabled !== "boolean") return null;
    return {
      pitrEnabled: json.pitr_enabled === true,
      walgEnabled: json.walg_enabled === true,
    };
  } catch {
    return null;
  }
}

/** Realtime publication state and auth hook definitions. */
export async function fetchRealtimeAndHooks(
  accessToken: string,
  projectRef: string,
  signal?: AbortSignal,
): Promise<{ realtimeTables?: RealtimeTableRow[]; authHooks?: AuthHookRow[] }> {
  // `undefined` on failure, never `[]` — the caller distinguishes "we could not
  // look" from "we looked and there was nothing", and collapsing them would make
  // an unreadable capability list read as a clean one.
  const attempt = async <T>(sql: string, source: string, schema: z.ZodType<T>) => {
    try {
      return await runReadQuery(accessToken, projectRef, sql, source, schema, signal);
    } catch {
      return undefined;
    }
  };
  const [realtimeTables, authHooks] = await Promise.all([
    attempt(REALTIME_SQL, "fetchRealtimeTables", RealtimeTableRowSchema),
    attempt(AUTH_HOOK_SQL, "fetchAuthHooks", AuthHookRowSchema),
  ]);
  return { realtimeTables, authHooks };
}


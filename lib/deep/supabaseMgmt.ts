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

// Vercel integration API access. Verified against Vercel docs (2026-07):
// integration API Scopes support per-scope None/Read/Read-Write plus per-project
// selection, so ShipLock's integration requests READ-only on projects/env for
// SELECTED projects only — a genuinely narrow grant (unlike Supabase's PAT).
// This module only ever READS; it never creates/updates/deletes anything.
import { env } from "@/lib/env";
import type { VercelEnvVar } from "./envaudit";

const API = "https://api.vercel.com";
const TIMEOUT_MS = 10_000;

function teamQs(teamId: string | null | undefined, extra = ""): string {
  const parts = [extra, teamId ? `teamId=${encodeURIComponent(teamId)}` : ""].filter(Boolean);
  return parts.length ? `?${parts.join("&")}` : "";
}

/**
 * Whether the Vercel connector can be offered at all.
 *
 * A connect button that links to a marketplace page which does not exist is the
 * fake affordance this product refuses to ship, so the UI hides the offer
 * entirely when these are unset rather than rendering a dead link.
 */
export function isVercelConfigured(): boolean {
  return Boolean(
    process.env.VERCEL_CLIENT_ID &&
      process.env.VERCEL_CLIENT_SECRET &&
      process.env.VERCEL_INTEGRATION_SLUG,
  );
}

/** Where a customer installs the integration. Vercel owns this flow. */
export function vercelInstallUrl(): string {
  return `https://vercel.com/integrations/${process.env.VERCEL_INTEGRATION_SLUG}/new`;
}

export interface VercelToken {
  accessToken: string;
  teamId: string | null;
  configurationId: string | null;
}

// Exchange the install `code` for an access token (classic integration OAuth).
export async function exchangeCodeForToken(code: string): Promise<VercelToken> {
  const clientId = env.VERCEL_CLIENT_ID;
  const clientSecret = env.VERCEL_CLIENT_SECRET;
  const redirectUri = `${env.NEXT_PUBLIC_APP_URL}/api/deep/vercel/callback`;
  if (!clientId || !clientSecret) throw new Error("VERCEL_CLIENT_ID and VERCEL_CLIENT_SECRET must be set");

  const res = await fetch(`${API}/v2/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Vercel token exchange HTTP ${res.status}`);
  const json = await res.json() as { access_token: string; team_id?: string | null; installation_id?: string | null };
  return {
    accessToken: json.access_token,
    teamId: json.team_id ?? null,
    configurationId: json.installation_id ?? null,
  };
}

export interface VercelProject { id: string; name: string; }

export async function listProjects(accessToken: string, teamId: string | null): Promise<VercelProject[]> {
  const res = await fetch(`${API}/v9/projects${teamQs(teamId)}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Vercel list projects HTTP ${res.status}`);
  const json = await res.json() as { projects?: Array<{ id: string; name: string }> };
  return (json.projects ?? []).map((p) => ({ id: p.id, name: p.name }));
}

// Read a project's env vars. decrypt=true returns plaintext values for
// non-sensitive vars; "sensitive"-typed vars come back without a value (null),
// which is fine — the name-based client-exposure check still applies to them.
export async function listProjectEnv(
  accessToken: string, projectIdOrName: string, teamId: string | null
): Promise<VercelEnvVar[]> {
  const res = await fetch(`${API}/v9/projects/${encodeURIComponent(projectIdOrName)}/env${teamQs(teamId, "decrypt=true")}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Vercel env read HTTP ${res.status}`);
  const json = await res.json() as { envs?: Array<{ key: string; value?: string | null; target?: string[]; type?: string }> };
  return (json.envs ?? []).map((e) => ({ key: e.key, value: e.value ?? null, target: e.target, type: e.type }));
}

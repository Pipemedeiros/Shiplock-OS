import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { currentConnectionEpoch } from "@/lib/deep/providerRepositoryMap";
import type { ProviderResult } from "./registry";

/**
 * Per-provider coverage from the latest snapshot (5A-3, migration 087). A
 * provider that is not connected is not listed; a read taken under an earlier
 * connection is never shown as current; a failed or partial read says what
 * was not read. This reports what was read, never that a provider is secure.
 */
type Transport = ProviderResult["transport"];
export type ProviderConnection = { transport: Transport; connected: boolean; identity: string | null; connectedAt: string | null };
export type SnapshotRow = z.infer<typeof snapshotRow>;
export type ProviderCoverageItem = {
  transport: Transport; label: string;
  state: "never_read" | "complete" | "partial" | "failed" | "stale_connection";
  observedAt: string | null; notRead: string[]; detail: string;
};

const snapshotRow = z.object({
  // supabase-edge-logs rows (088) belong to the traffic card, not this one.
  transport: z.enum(["postgres-direct", "supabase-management", "vercel", "app-surface", "supabase-edge-logs"]),
  connection_identity: z.string().nullable(), observed_at: z.string(),
  completeness: z.enum(["complete", "partial", "failed"]), unread: z.array(z.string()),
  reason: z.string().nullable(), finding_count: z.number().nullable(), scope: z.string().nullable(),
});

const LABELS: Record<Transport, string> = {
  "supabase-management": "Supabase project", "postgres-direct": "Postgres database",
  vercel: "Vercel", "app-surface": "Live app",
};

// Finding-ID prefix to what the customer would call it. Longest match wins.
const FAMILIES: [string, string][] = [
  ["advisor:", "Supabase security advisors"], ["auth_redirect:", "Auth settings"], ["auth_site_url:", "Auth settings"],
  ["auth_policy:", "Auth settings"], ["auth_hook:", "Auth hooks"], ["grants:", "Column grants"],
  ["extensions:in_public_schema", "Extensions"], ["extensions:network_callable_by_public_role", "Network access from the database"],
  ["extensions:cron_", "Scheduled jobs"], ["extensions:foreign_servers", "Foreign servers"],
  ["storage:unrestricted_uploads:", "Storage buckets"], ["storage:permissive_object_policy", "Storage policies"],
  ["storage:no_pitr", "Backups"], ["realtime:", "Realtime"], ["exposed:", "Exposed paths"],
  ["bundle:", "Shipped JavaScript"], ["email_auth:", "Email authentication records"], ["origin:", "Origin server"],
];

const REASONS: Record<string, string> = {
  auth_failed: "ShipLock's access was refused. Reconnect to read it again.",
  not_committed: "The connection changed during the read, so nothing from it was kept.",
  timeout: "The provider did not answer in time.",
  not_connected: "The connection could not be used.",
};

function familyName(prefix: string): string {
  const vercel = /^vercel:(.+):$/.exec(prefix);
  if (vercel) return `Vercel project ${vercel[1]}`;
  const match = FAMILIES.filter(([p]) => prefix.startsWith(p) || p.startsWith(prefix)).sort((a, b) => b[0].length - a[0].length)[0];
  return match ? match[1] : "Some checks";
}

export function summarizeProviderCoverage(connections: ProviderConnection[], rows: SnapshotRow[]): ProviderCoverageItem[] {
  return connections.filter((c) => c.connected).map((connection) => {
    const base = { transport: connection.transport, label: LABELS[connection.transport] };
    const latest = rows.filter((r) => r.transport === connection.transport)
      .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))[0];
    if (!latest) {
      return { ...base, state: "never_read" as const, observedAt: null, notRead: [], detail: "Connected. ShipLock has not read it yet." };
    }
    const stale = latest.connection_identity !== null
      ? latest.connection_identity !== connection.identity
      : connection.connectedAt !== null && Date.parse(latest.observed_at) < Date.parse(connection.connectedAt);
    if (stale) {
      return { ...base, state: "stale_connection" as const, observedAt: null, notRead: [],
        detail: "Reconnected. ShipLock has not read the new connection yet, so earlier reads are not shown as current." };
    }
    if (latest.completeness === "failed") {
      return { ...base, state: "failed" as const, observedAt: latest.observed_at, notRead: [],
        detail: `The last read failed. ${REASONS[latest.reason ?? ""] ?? "Nothing from it was kept."} Open findings stay open.` };
    }
    const notRead = [...new Set(latest.unread.map(familyName))];
    if (latest.completeness === "partial") {
      return { ...base, state: "partial" as const, observedAt: latest.observed_at, notRead,
        detail: "Part of it could not be read. Findings in those areas stay open until a read succeeds." };
    }
    return { ...base, state: "complete" as const, observedAt: latest.observed_at, notRead: [],
      detail: "Everything ShipLock checks here was read. That is not a statement that it is secure." };
  });
}

/** The caller's connected providers and their latest snapshots. */
export async function getProviderCoverage(userId: string): Promise<{ available: boolean; items: ProviderCoverageItem[] }> {
  const admin = getSupabaseAdmin();
  const [profileRead, rowsRead] = await Promise.all([
    admin.from("user_profiles").select(
      "supabase_mgmt_token_encrypted, supabase_mgmt_connection_epoch, supabase_mgmt_connected_at, postgres_dsn_encrypted, postgres_connection_epoch, postgres_connected_at, vercel_access_token_encrypted, vercel_connection_epoch, vercel_connected_at, monitored_app_url",
    ).eq("id", userId).maybeSingle(),
    admin.from("provider_snapshots")
      .select("transport, connection_identity, observed_at, completeness, unread, reason, finding_count, scope")
      .eq("user_id", userId).order("observed_at", { ascending: false }).limit(40),
  ]);
  const rows = z.array(snapshotRow).safeParse(rowsRead.data ?? []);
  if (profileRead.error || rowsRead.error || !rows.success) return { available: false, items: [] };
  const p = (profileRead.data ?? {}) as Record<string, string | null | undefined>;
  const epochOf = (cipher: string, epoch: string) => currentConnectionEpoch(p[cipher], p[epoch]) ?? null;
  const connections: ProviderConnection[] = [
    { transport: "supabase-management", identity: epochOf("supabase_mgmt_token_encrypted", "supabase_mgmt_connection_epoch"), connectedAt: p.supabase_mgmt_connected_at ?? null, connected: false },
    { transport: "postgres-direct", identity: epochOf("postgres_dsn_encrypted", "postgres_connection_epoch"), connectedAt: p.postgres_connected_at ?? null, connected: false },
    { transport: "vercel", identity: epochOf("vercel_access_token_encrypted", "vercel_connection_epoch"), connectedAt: p.vercel_connected_at ?? null, connected: false },
    { transport: "app-surface", identity: p.monitored_app_url ?? null, connectedAt: null, connected: false },
  ].map((c) => ({ ...c, connected: c.identity !== null }) as ProviderConnection);
  return { available: true, items: summarizeProviderCoverage(connections, rows.data) };
}

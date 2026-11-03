/**
 * Finding-ID prefixes whose Supabase read failed in this pass.
 * The fenced commit retires active findings absent from a pass, except those
 * under an unread prefix, so a failed read keeps its family's findings open
 * instead of archiving them as fixed. `undefined`/`null` means "could not
 * look"; an empty list means "looked and found none".
 */
type Read<T> = T | null | undefined;

/** The check families a Supabase pass could not read, shown as unread rather
 * than clean. */
export function unreadSupabaseFamilies(reads: {
  advisorsOk: boolean;
  authConfig: unknown;
  grants: Read<unknown[]>;
  capabilities: { extensions?: unknown[]; networkGrants?: unknown[]; cronJobs?: unknown[]; foreignServers?: unknown[] };
  storage: { buckets?: unknown[]; policies?: unknown[] };
  backups: unknown;
  realtime: { realtimeTables?: unknown[]; authHooks?: unknown[] };
}): string[] {
  const unread: string[] = [];
  const miss = (value: unknown, ...prefixes: string[]) => { if (value == null) unread.push(...prefixes); };
  if (!reads.advisorsOk) unread.push("advisor:");
  miss(reads.authConfig, "auth_redirect:", "auth_site_url:", "auth_policy:");
  miss(reads.grants, "grants:");
  miss(reads.capabilities.extensions, "extensions:in_public_schema");
  miss(reads.capabilities.networkGrants, "extensions:network_callable_by_public_role");
  miss(reads.capabilities.cronJobs, "extensions:cron_");
  miss(reads.capabilities.foreignServers, "extensions:foreign_servers");
  miss(reads.storage.buckets, "storage:unrestricted_uploads:");
  miss(reads.storage.policies, "storage:permissive_object_policy");
  miss(reads.backups, "storage:no_pitr");
  miss(reads.realtime.realtimeTables, "realtime:");
  miss(reads.realtime.authHooks, "auth_hook:");
  return unread;
}

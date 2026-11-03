import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Traffic sites (migration 085): one public app host bound to one of
 * the customer's selected repositories, with its own snippet token. A site
 * token ties every event to that repository; the legacy per-account token
 * still works but its traffic stays unbound and never corroborates a
 * repository's findings.
 *
 * Entitlement is unchanged from before 2F: traffic requires `is_paid`. Whether
 * traffic is free is PARKED by Felipe (2026-09-23); do not widen this here.
 */
const trafficEntitled = (profile: { is_paid?: unknown }) => profile.is_paid === true;
export type TrafficIdentity = { userId: string; email: string | null; siteId: string | null; repositoryId: string | null };

const UUID = z.uuid();

/**
 * The same checks as a token, for a site addressed by id: ShipLock's own proxy
 * (selfObserve.ts) files its traffic this way, so no token is needed in config.
 */
export async function resolveTrafficSiteById(siteId: string): Promise<TrafficIdentity | null> {
  if (!UUID.safeParse(siteId).success) return null;
  const admin = getSupabaseAdmin();
  const { data: site } = await admin.from("traffic_sites").select("id, user_id, repository_id")
    .eq("id", siteId).is("revoked_at", null).maybeSingle();
  if (!site) return null;
  const { data: profile } = await admin.from("user_profiles").select("id, email, is_paid").eq("id", site.user_id).maybeSingle();
  if (!profile || !trafficEntitled(profile)) return null;
  const { data: repository } = await admin.from("repositories").select("id")
    .eq("id", site.repository_id).eq("user_id", site.user_id).eq("selected", true).maybeSingle();
  if (!repository) return null;
  return { userId: profile.id as string, email: (profile.email as string | null) ?? null,
    siteId: site.id as string, repositoryId: site.repository_id as string };
}

/** The account and repository behind a traffic ingest token, or null when
 * revoked or not entitled. */
export async function resolveTrafficToken(token: string): Promise<TrafficIdentity | null> {
  if (!UUID.safeParse(token).success) return null;
  const admin = getSupabaseAdmin();
  const { data: site } = await admin.from("traffic_sites").select("id, user_id, repository_id")
    .eq("ingest_token", token).is("revoked_at", null).maybeSingle();
  const userId = site ? (site.user_id as string) : null;
  const { data: profile } = await admin.from("user_profiles").select("id, email, is_paid")
    .eq(site ? "id" : "traffic_ingest_token", site ? userId : token).maybeSingle();
  if (!profile || !trafficEntitled(profile)) return null;
  if (!site) return { userId: profile.id as string, email: (profile.email as string | null) ?? null, siteId: null, repositoryId: null };
  // A deselected repository stops accepting its site's traffic.
  const { data: repository } = await admin.from("repositories").select("id")
    .eq("id", site.repository_id).eq("user_id", userId).eq("selected", true).maybeSingle();
  if (!repository) return null;
  return { userId: profile.id as string, email: (profile.email as string | null) ?? null,
    siteId: site.id as string, repositoryId: site.repository_id as string };
}

const created = z.array(z.object({ site_id: z.uuid(), ingest_token: z.uuid() })).length(1);

/** Binds a public app host to a repository and returns its ingest token. */
export async function createTrafficSite(userId: string, repositoryId: string, host: string): Promise<{ siteId: string; ingestToken: string }> {
  const { data, error } = await getSupabaseAdmin().rpc("create_traffic_site", { p_user: userId, p_repository: repositoryId, p_host: host });
  if (error) {
    const code = ["host already bound", "invalid host", "repository unavailable"].find((m) => error.message.includes(m));
    throw new Error(code ? code.replace(/ /g, "_") : "traffic_site_unwritable");
  }
  const row = created.parse(data)[0];
  return { siteId: row.site_id, ingestToken: row.ingest_token };
}

/** Revokes a traffic site; false when it was not the account's. */
export async function revokeTrafficSite(userId: string, siteId: string): Promise<boolean> {
  const { data, error } = await getSupabaseAdmin().rpc("revoke_traffic_site", { p_user: userId, p_site: siteId });
  if (error) throw new Error("traffic_site_unwritable");
  return data === true;
}

const listed = z.array(z.object({ id: z.uuid(), host: z.string(), created_at: z.string(),
  repositories: z.object({ full_name: z.string() }) }));

/** The caller's active sites, never their tokens. */
export async function listTrafficSites(userId: string): Promise<{ siteId: string; host: string; repository: string; createdAt: string }[]> {
  const { data, error } = await getSupabaseAdmin().from("traffic_sites")
    .select("id, host, created_at, repositories(full_name)").eq("user_id", userId).is("revoked_at", null);
  if (error) throw new Error("traffic_sites_unreadable");
  return listed.parse(data ?? []).map((row) => ({ siteId: row.id, host: row.host, repository: row.repositories.full_name, createdAt: row.created_at }));
}

import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { SurfaceChange } from "@/lib/security/surfaceChange";

/**
 * Reach observed on the founder's live site (the outside view), admitted
 * for one repository. The app-surface pass stores the paths the site's
 * JavaScript names as a runtime fact (lib/security/exposedPathsRun.ts); that
 * fact joins a repository's findings only when all of these hold (AGENTS.md:
 * a join needs the selected repository, a current connection and a customer
 * confirmation):
 *
 *   - the founder confirmed the address for that repository, and the address
 *     is still the one confirmed (any later change ends the join);
 *   - the repository is still selected;
 *   - the fact was read from that same address.
 *
 * Anything else is no join, never "not reachable".
 */
export type LiveReach = {
  repositoryId: string; host: string; observedAt: string | null; paths: string[];
  /** Paths requested on the site's own origin; null on a fact read before they were recorded. */
  requests: string[] | null;
  read: { pages: number | null; scriptsSeen: number | null; scriptsRead: number | null };
  /** What the site started or stopped requesting since the read before (lib/security/surfaceChange.ts). */
  change: SurfaceChange | null;
};

type Profile = { monitored_app_url?: unknown; monitored_app_repository_id?: unknown; monitored_app_bound_url?: unknown };
const PLAIN = /^\/[A-Za-z0-9_\-.~/[\]:@]{1,199}$/;
const Count = z.number().int().nonnegative().optional();
const Paths = z.array(z.string().regex(PLAIN)).max(500);
const Change = z.union([
  z.object({ comparable: z.literal(true), since: z.string().nullable(), added: Paths, removed: Paths }),
  z.object({ comparable: z.literal(false), since: z.string().nullable() }),
]);
const Fact = z.object({ url: z.string(), paths: z.array(z.string()).max(500), requests: z.array(z.string()).max(500).optional(),
  pagesRead: Count, scriptsSeen: Count, scriptsRead: Count, change: z.unknown().optional() });

export function liveReachFrom(profile: Profile | null, runtime: Record<string, unknown> | null, selected: readonly string[]): LiveReach | null {
  if (!profile || !runtime) return null;
  const url = profile.monitored_app_url, repositoryId = profile.monitored_app_repository_id;
  if (typeof url !== "string" || typeof repositoryId !== "string") return null;
  if (profile.monitored_app_bound_url !== url || !selected.includes(repositoryId)) return null;
  const fact = Fact.safeParse(runtime.appSurface);
  if (!fact.success || fact.data.url !== url) return null;
  const evidence = runtime._evidence as { fields?: { appSurface?: { recordedAt?: unknown } } } | undefined;
  const recordedAt = evidence?.fields?.appSurface?.recordedAt;
  let host: string;
  try { host = new URL(url).host; } catch { return null; }
  const { paths, requests, pagesRead, scriptsSeen, scriptsRead } = fact.data;
  const change = Change.safeParse(fact.data.change);
  return { repositoryId, host, observedAt: typeof recordedAt === "string" ? recordedAt : null,
    paths: paths.filter((p) => PLAIN.test(p)), requests: requests ? requests.filter((p) => PLAIN.test(p)) : null,
    read: { pages: pagesRead ?? null, scriptsSeen: scriptsSeen ?? null, scriptsRead: scriptsRead ?? null },
    change: change.success ? change.data : null };
}

/** The account's live reach, or null when nothing is bound or readable. */
export async function loadLiveReach(userId: string): Promise<LiveReach | null> {
  const admin = getSupabaseAdmin();
  const [profile, facts, repos] = await Promise.all([
    admin.from("user_profiles").select("monitored_app_url, monitored_app_repository_id, monitored_app_bound_url").eq("id", userId).maybeSingle(),
    admin.from("graph_facts").select("facts").eq("user_id", userId).eq("collector", "runtime").maybeSingle(),
    admin.from("repositories").select("id").eq("user_id", userId).eq("selected", true),
  ]);
  if (profile.error || facts.error || repos.error) return null;
  return liveReachFrom(profile.data as Profile | null, (facts.data?.facts as Record<string, unknown> | undefined) ?? null,
    ((repos.data ?? []) as { id: string }[]).map((r) => r.id));
}

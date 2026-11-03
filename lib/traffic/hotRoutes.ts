import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listTree } from "@/lib/deep/github";
import { matchHotPaths } from "./routeMatch";

/**
 * Observed hot routes per selected repository: the routes a
 * rate-limit PR could be offered for. Read-only; at most 5 repositories and 3
 * routes each; any GitHub or read error leaves that repository out rather
 * than guessing.
 */
export type HotRouteOffer = { file: string; pattern: string; suspiciousRequests: number };

/** Routes that observed suspicious traffic, per repository, matched to their
 * files. */
export async function getHotRoutes(userId: string): Promise<Record<string, HotRouteOffer[]>> {
  const admin = getSupabaseAdmin();
  const [profile, observations] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle(),
    admin.from("traffic_route_observations").select("repository_id, path, suspicious_requests").eq("user_id", userId),
  ]);
  const installationId = profile.data?.github_installation_id as number | null | undefined;
  const rows = (observations.data ?? []) as { repository_id: string; path: string; suspicious_requests: number }[];
  if (profile.error || observations.error || !installationId || rows.length === 0) return {};
  const repositoryIds = [...new Set(rows.map((r) => r.repository_id))].slice(0, 5);
  const repositories = await admin.from("repositories").select("id, full_name, default_branch, selected")
    .eq("user_id", userId).in("id", repositoryIds);
  if (repositories.error) return {};
  let token: string;
  try { token = await getInstallationToken(installationId); } catch { return {}; }
  const offers: Record<string, HotRouteOffer[]> = {};
  await Promise.all(((repositories.data ?? []) as { id: string; full_name: string; default_branch: string; selected: boolean }[])
    .filter((repository) => repository.selected).map(async (repository) => {
      try {
        const files = (await listTree(token, repository.full_name, repository.default_branch)).map((entry) => entry.path);
        const hot = rows.filter((r) => r.repository_id === repository.id)
          .map((r) => ({ path: r.path, suspiciousRequests: r.suspicious_requests }));
        const matched = matchHotPaths(hot, files).matched.slice(0, 3);
        if (matched.length) offers[repository.id] = matched.map(({ file, pattern, suspiciousRequests }) => ({ file, pattern, suspiciousRequests }));
      } catch { /* left out: unknown is not offered */ }
    }));
  return offers;
}

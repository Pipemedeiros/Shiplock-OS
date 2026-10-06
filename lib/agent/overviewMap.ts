import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { getHotRoutes, type HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { buildRouteMap, type RouteMap } from "@/lib/routeMap";
import type { DashboardFinding, DashboardRepo, DashboardRun } from "@/lib/agent/dashboardData";

/**
 * The route map the Overview draws, shared with the security loop so both
 * count the same exposed routes. Q27: built from the last finished audit's
 * stored route facts; the source snapshot is read only when an older run has
 * none.
 */
export async function loadOverviewMap(input: {
  userId: string; runs: DashboardRun[]; latest: DashboardRun | null; repos: DashboardRepo[]; findings: DashboardFinding[];
}): Promise<{ map: RouteMap | null; mapRepo: DashboardRepo; hot: Record<string, HotRouteOffer[]> }> {
  const { userId, runs, latest, repos, findings } = input;
  const mapRepo = repos.find((r) => r.fullName === latest?.fullName) ?? repos[0];
  const auditRoutes = runs.find((r) => r.fullName === mapRepo.fullName && r.routeFacts)?.routeFacts ?? null;
  const noHot: Record<string, HotRouteOffer[]> = {};
  const [source, hot] = latest
    ? await Promise.all([auditRoutes ? null : loadRepositoryGraphSource(userId, mapRepo.id), getHotRoutes(userId).catch(() => noHot)])
    : [null, noHot];
  const mapRoutes = auditRoutes ?? (source?.routes?.length ? source.routes : null);
  const map = mapRoutes
    ? buildRouteMap({
        routes: mapRoutes,
        tools: latest?.stack?.tools ?? [],
        findings: findings.filter((f) => f.repositoryId === mapRepo.id),
        hotFiles: (hot[mapRepo.id] ?? []).map((h) => h.file),
      })
    : null;
  return { map, mapRepo, hot };
}

/** Routes on the map, and those reachable without a check that scopes them. */
export function mapCounts(map: RouteMap | null): { routes: number; exposed: number } {
  const routes = map?.nodes.filter((n) => n.kind === "route") ?? [];
  return { routes: routes.length, exposed: routes.filter((n) => n.exposure === "open" || n.exposure === "unscoped").length };
}

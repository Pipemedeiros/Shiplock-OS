import { getOpenFindings, getRepositories, getRuns, type DashboardFinding, type DashboardRun } from "@/lib/agent/dashboardData";
import { getRecentPullRequestReviews, type PullRequestReviewView } from "@/lib/agent/pullRequestReviews";
import { loadOverviewMap, mapCounts } from "@/lib/agent/overviewMap";
import { getAiActivity, type AiActivity } from "@/lib/intelligence/activity";
import { getProviderCoverage, type ProviderCoverageItem } from "@/lib/monitoring/providerCoverage";
import { listTrafficSites } from "@/lib/traffic/sites";
import { auditState } from "@/lib/verdict";
import type { LoopInput } from "@/lib/securityLoop";

/** The loop's input from rows the dashboard already reads (pure, tested). */
export function loopInputOf(input: {
  runs: DashboardRun[]; ai: AiActivity; map: { routes: number; exposed: number } | null;
  findings: DashboardFinding[]; reviews: PullRequestReviewView[]; trafficSites: number; hotRoutes: number;
  providers: { available: boolean; items: ProviderCoverageItem[] };
}): LoopInput {
  const { current, finished } = auditState(input.runs);
  const checks = input.ai.available ? input.ai.checks : [];
  return {
    current: current ? { status: current.status as "queued" | "running", step: current.trace.at(-1)?.label ?? null } : null,
    finished: finished ? { status: finished.status as "complete" | "failed", filesRead: finished.filesRead ?? 0,
      entries: finished.entriesFound ?? 0, tables: finished.tablesFound ?? 0, unread: finished.coverage.length } : null,
    agent: { available: input.ai.available, paused: input.ai.available ? input.ai.paused : null,
      pending: checks.filter((c) => c.state === "pending").length,
      answered: checks.filter((c) => c.state === "proposal" || c.state === "needs_human").length },
    map: finished ? input.map : null,
    fix: { open: input.findings.length, withPr: input.findings.filter((f) => f.fixPrUrl).length },
    watch: { prChecks: input.reviews.length, blockedPrs: input.reviews.filter((r) => r.verdict === "block").length,
      trafficSites: input.trafficSites, hotRoutes: input.hotRoutes,
      providersRead: input.providers.items.filter((p) => p.state === "complete" || p.state === "partial").length,
      providersConnected: input.providers.items.length },
  };
}

/** Read everything the loop shows for one signed-in customer. */
export async function loadSecurityLoopInput(userId: string): Promise<LoopInput> {
  const [runs, repos, findings, ai, reviews, sites, providers] = await Promise.all([
    getRuns(userId, 5), getRepositories(userId), getOpenFindings(userId), getAiActivity(userId),
    getRecentPullRequestReviews(userId).catch(() => []), listTrafficSites(userId).catch(() => []),
    getProviderCoverage(userId).catch(() => ({ available: false, items: [] })),
  ]);
  const { finished } = auditState(runs);
  const overview = repos.length > 0 ? await loadOverviewMap({ userId, runs, latest: finished, repos, findings }) : null;
  return loopInputOf({ runs, ai, map: overview?.map ? mapCounts(overview.map) : null, findings, reviews,
    trafficSites: sites.length, hotRoutes: Object.values(overview?.hot ?? {}).reduce((sum, list) => sum + list.length, 0),
    providers });
}

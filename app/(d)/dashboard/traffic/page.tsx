import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { loadOverviewMap } from "@/lib/agent/overviewMap";
import { auditState } from "@/lib/verdict";
import { listTrafficSites } from "@/lib/traffic/sites";
import { EMPTY_PULSE, getTrafficPulse } from "@/lib/traffic/pulse";
import { getProtectionStatus } from "@/lib/traffic/trafficLog";
import { loadAttackRows } from "@/lib/traffic/attackData";
import { buildAttackView } from "@/lib/traffic/attackView";
import { TrafficView } from "@/components/v3/TrafficView";
import { LiveRefresh } from "@/components/v3/LiveRefresh";

export const metadata = { title: "Traffic" };

/**
 * Traffic (Felipe 2026-10-16): requests, flagged sources, the routes they
 * attacked on the map, and which of those has an open issue. Server side,
 * from the customer's own rows; the page refreshes while traffic arrives.
 */
export default async function TrafficPage() {
  const { userId } = await requireDashboardSession();
  const [findings, runs, repos, sites] = await Promise.all([
    getOpenFindings(userId), getRuns(userId, 5), getRepositories(userId), listTrafficSites(userId).catch(() => null),
  ]);
  const repository = repos[0]?.fullName ?? "No repository";
  if (!sites || sites.length === 0 || repos.length === 0) {
    return <TrafficView repository={repository} sites={sites?.length ?? 0} installed={false} lastSeenAt={null}
      pulse={EMPTY_PULSE} view={null} map={null} capped={false} />;
  }

  const { finished: latest } = auditState(runs);
  const [pulse, status, rows, overview] = await Promise.all([
    getTrafficPulse(userId).catch(() => EMPTY_PULSE),
    getProtectionStatus(userId).catch(() => ({ installed: false, lastSeenAt: null })),
    loadAttackRows(userId).catch(() => ({ available: false as const })),
    loadOverviewMap({ userId, runs, latest, repos, findings }),
  ]);
  const mapRepo = overview.mapRepo;
  const routes = runs.find((r) => r.fullName === mapRepo.fullName && r.routeFacts)?.routeFacts ?? [];
  const view = rows.available
    ? buildAttackView({ now: rows.now, alerts: rows.alerts, blocks: rows.blocks, events: rows.events,
        routes: routes.map((r) => ({ path: r.path, file: r.file })),
        findings: findings.filter((f) => f.repositoryId === mapRepo.id) })
    : null;

  return (
    <>
      <LiveRefresh active={status.installed} everyMs={15_000} />
      <TrafficView repository={mapRepo.fullName} sites={sites.length} installed={status.installed} lastSeenAt={status.lastSeenAt}
        pulse={pulse} view={view} map={overview.map} capped={rows.available ? rows.capped : false} />
    </>
  );
}

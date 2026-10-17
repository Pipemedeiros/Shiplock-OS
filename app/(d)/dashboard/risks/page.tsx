import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { listTrafficSites } from "@/lib/traffic/sites";
import { withChains } from "@/lib/chain/findingChains";
import { loadLiveReach } from "@/lib/chain/liveReach";
import { loadSelfCheckReports } from "@/lib/proof/selfCheckReports";
import { RisksBoard } from "@/components/v3/RisksBoard";
import { getProofViews, proofOffers, provingEnabled } from "@/lib/proving/proofStatus";
import { getHotRoutes } from "@/lib/traffic/hotRoutes";
import { withTraffic } from "@/lib/traffic/findingTraffic";

export const metadata = { title: "Issues" };

export default async function Risks() {
  const { userId } = await requireDashboardSession();
  const [open, enabled, views, hot, runs, repos, sites, live, reports] = await Promise.all([getOpenFindings(userId), provingEnabled(userId), getProofViews(userId),
    getHotRoutes(userId).catch(() => ({})), getRuns(userId).catch(() => []), getRepositories(userId).catch(() => []),
    listTrafficSites(userId).catch(() => null), loadLiveReach(userId).catch(() => null), loadSelfCheckReports(userId).catch(() => new Map())]);
  // Traffic orders what to look at first; it never changes a severity. The
  // evidence chain explains each issue; an unread input leaves its link unknown.
  const findings = withChains(withTraffic(open, hot), { runs, repos, trafficConnected: (sites?.length ?? 0) > 0, live, reports });
  const proofs = proofOffers(findings, enabled, views);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <h1>Issues</h1>
        </div>
      </div>
      <RisksBoard findings={findings} proofs={proofs} />
    </>
  );
}

import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { RisksBoard } from "@/components/v3/RisksBoard";
import { getProofViews, proofOffers, provingEnabled } from "@/lib/proving/proofStatus";
import { getHotRoutes } from "@/lib/traffic/hotRoutes";
import { withTraffic } from "@/lib/traffic/findingTraffic";

export const metadata = { title: "Issues" };

export default async function Risks() {
  const { userId } = await requireDashboardSession();
  const [open, enabled, views, hot] = await Promise.all([getOpenFindings(userId), provingEnabled(userId), getProofViews(userId),
    getHotRoutes(userId).catch(() => ({}))]);
  // Traffic orders what to look at first; it never changes a severity.
  const findings = withTraffic(open, hot);
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

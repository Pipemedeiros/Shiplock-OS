import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { RisksBoard } from "@/components/v3/RisksBoard";
import { getProofViews, proofOffers, provingEnabled } from "@/lib/proving/proofStatus";

export default async function Risks() {
  const { userId } = await requireDashboardSession();
  const [findings, enabled, views] = await Promise.all([getOpenFindings(userId), provingEnabled(userId), getProofViews(userId)]);
  const proofs = proofOffers(findings, enabled, views);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">Ordered by what they reach</p>
          <h1 className="v3-serif">Every way in, and the check that is missing.</h1>
        </div>
      </div>
      <RisksBoard findings={findings} proofs={proofs} />
    </>
  );
}

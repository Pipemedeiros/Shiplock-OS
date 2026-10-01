import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { RisksBoard } from "@/components/v3/RisksBoard";
import { getProofViews, proofOffers, provingEnabled } from "@/lib/proving/proofStatus";

export const metadata = { title: "Issues" };

export default async function Risks() {
  const { userId } = await requireDashboardSession();
  const [findings, enabled, views] = await Promise.all([getOpenFindings(userId), provingEnabled(userId), getProofViews(userId)]);
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

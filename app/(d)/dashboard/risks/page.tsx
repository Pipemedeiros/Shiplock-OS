import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { RisksBoard } from "@/components/v3/RisksBoard";

export default async function Risks() {
  const { userId } = await requireDashboardSession();
  const findings = await getOpenFindings(userId);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">Ordered by what they reach</p>
          <h1 className="v3-serif">Every way in, and the check that is missing.</h1>
        </div>
      </div>
      <RisksBoard findings={findings} />
    </>
  );
}

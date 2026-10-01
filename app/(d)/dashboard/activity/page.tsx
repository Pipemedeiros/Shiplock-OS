import { requireDashboardSession } from "@/lib/dashboard";
import { getRecentlyClosed, getRuns } from "@/lib/agent/dashboardData";
import { RunList } from "@/components/v3/RunList";
import { When } from "@/components/v3/When";

export const metadata = { title: "Activity" };

export default async function ActivityPage() {
  const { userId } = await requireDashboardSession();
  const [runs, closed] = await Promise.all([getRuns(userId), getRecentlyClosed(userId)]);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">Everything we did, and when</p>
          <h1 className="v3-serif">Activity</h1>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Audit runs</h2>
            <span className="v3-small">Open one to read it line by line</span>
          </div>
          <div className="v3-card-p">
            {runs.length === 0 ? (
              <p className="v3-small">No audits yet.</p>
            ) : (
              <RunList runs={runs} />
            )}
          </div>
        </div>

        {closed.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Closed</h2>
              <span className="v3-small">Last 30 days</span>
            </div>
            <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {closed.map((c) => (
                <div key={`${c.title}-${c.when}`} className="v3-between">
                  <div className="v3-row" style={{ gap: 10 }}>
                    <span className="v3-tag ok">closed</span>
                    <span style={{ fontSize: 14 }}>{c.title}</span>
                  </div>
                  <span className="v3-small"><When at={c.when} date /></span>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}

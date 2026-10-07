import { requireDashboardSession } from "@/lib/dashboard";
import { getAttackTasks, getRecentlyClosed, getRuns } from "@/lib/agent/dashboardData";
import { attackFeed } from "@/lib/agent/attackFeed";
import { AttackFeedCard } from "@/components/v3/AttackFeed";
import { RunList } from "@/components/v3/RunList";
import { When } from "@/components/v3/When";
import { SecurityLoop } from "@/components/v3/SecurityLoop";
import { LiveRefresh } from "@/components/v3/LiveRefresh";
import { loadSecurityLoopInput } from "@/lib/agent/securityLoopData";
import { securityLoop } from "@/lib/securityLoop";

export const metadata = { title: "Activity" };

export default async function ActivityPage() {
  const { userId } = await requireDashboardSession();
  const [runs, closed, loop, attackTasks] = await Promise.all([getRuns(userId), getRecentlyClosed(userId), loadSecurityLoopInput(userId),
    getAttackTasks(userId).catch(() => null)]);
  // A3: the attack as it happens, from the agent's real task states. An
  // unreadable read shows nothing rather than a state we did not read.
  const feed = attackTasks ? attackFeed(attackTasks) : null;

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <h1>Activity</h1>
        </div>
      </div>

      <div className="v3-stack">
        <LiveRefresh active={loop.current !== null || feed?.phase === "waiting_for_agent" || feed?.phase === "checking"} />
        <SecurityLoop stages={securityLoop(loop)} />
        {feed ? <AttackFeedCard feed={feed} /> : null}

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Audits</h2>
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

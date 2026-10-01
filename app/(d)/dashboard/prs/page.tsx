import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { getRecentPullRequestReviews } from "@/lib/agent/pullRequestReviews";
import { Sev } from "@/components/v3/FindingParts";
import { getAiActivity } from "@/lib/intelligence/activity";
import { OpenedPullRequests } from "@/components/v3/OpenedPullRequests";
import { getOpenedPullRequests } from "@/lib/fixes/openedPullRequests";
import { getCiStatuses } from "@/lib/fixes/prCiStatus";
import { Fold } from "@/components/v3/Fold";
import { CheckedPullRequests } from "@/components/v3/CheckedPullRequests";

/**
 * The pull requests ShipLock opened, waiting on a human.
 *
 * This is the page the product is for. Everything else — the audit, the graph,
 * the evidence ledger — exists so that this list is short, correct, and worth
 * the thirty seconds it takes to read one. A finding that never becomes a
 * reviewable change is a piece of homework we handed back.
 *
 * Two things are said plainly here rather than implied, because both are what
 * makes an autonomous tool safe to leave running:
 *   - Nothing is ever merged by us. The branch sits there until they merge it.
 *   - The authorization logic inside is not machine-authored. The pull request
 *     carries the finding, the evidence and a precise instruction; the decision
 *     about which column identifies a tenant stays with the person who knows.
 */
export const metadata = { title: "Pull requests" };

export default async function PullRequests() {
  const { userId } = await requireDashboardSession();
  const [findings, reviews, ai, opened] = await Promise.all([getOpenFindings(userId), getRecentPullRequestReviews(userId),
    getAiActivity(userId), getOpenedPullRequests(userId)]);
  const ci = await getCiStatuses(userId, opened.items);

  const eligible = findings.filter((f) => !f.fixPrUrl && f.fixKind === "pr");
  const manual = findings.filter((f) => !f.fixPrUrl && f.fixKind !== "pr");

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <h1>Pull requests</h1>
          <p className="v3-small" style={{ marginTop: 6 }}>Checked automatically. Fixes open only when you click. ShipLock never merges.</p>
        </div>
      </div>

      <div className="v3-stack">
        <CheckedPullRequests reviews={reviews} ai={ai} />

        {/* Every lane's clicked pull request, open or merged (Q1 / 8-R2). */}
        <OpenedPullRequests opened={opened} ci={ci} />

        {eligible.length > 0 ? (
          <Fold title="Ready to fix" status={`${eligible.length} without a pull request`}>
            <div>
              <p className="v3-small" style={{ marginBottom: 12 }}>
                Open a fix from Issues. Nothing is opened without your click.
              </p>
              <div className="v3-list">
                {eligible.map((f) => (
                  <div key={f.rowId} className="v3-between v3-row-pad">
                    <span style={{ fontSize: 14 }}>{f.title}</span>
                    <Sev severity={f.severity} />
                  </div>
                ))}
              </div>
            </div>
          </Fold>
        ) : null}

        {manual.length > 0 ? (
          <Fold title="Manual fixes" status={`${manual.length} need your decision`}>
            <div>
              <p className="v3-small" style={{ marginBottom: 12 }}>
                Architecture decisions, not mechanical changes, so ShipLock does not write the patch.
              </p>
              <div className="v3-list">
                {manual.map((f) => (
                  <div key={f.rowId} className="v3-between v3-row-pad">
                    <span style={{ fontSize: 14 }}>{f.title}</span>
                    <Sev severity={f.severity} />
                  </div>
                ))}
              </div>
              <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 12 }}>
                View issues
              </Link>
            </div>
          </Fold>
        ) : null}
      </div>
    </>
  );
}

import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getAttackTasks, getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { attackFeed } from "@/lib/agent/attackFeed";
import { AttackSummary } from "@/components/v3/AttackFeed";
import { Sev } from "@/components/v3/FindingParts";
import { RunAuditButton } from "@/components/v3/RunAuditButton";
import { LiveRefresh } from "@/components/v3/LiveRefresh";
import { HitHard } from "@/components/v3/HitHard";
import { withTraffic } from "@/lib/traffic/findingTraffic";
import { RouteMap } from "@/components/v3/RouteMap";
import { loadOverviewMap, mapCounts } from "@/lib/agent/overviewMap";
import { When } from "@/components/v3/When";
import { Metric, Verdict } from "@/components/v3/Verdict";
import { auditState, verdictOf } from "@/lib/verdict";
import { getRecentPullRequestReviews } from "@/lib/agent/pullRequestReviews";
import { loadLiveReach } from "@/lib/chain/liveReach";
import { notCheckedAreas, shadowRoutesFromRuns } from "@/lib/chain/shadowRoutes";

export const metadata = { title: "Overview" };

/**
 * Overview, in the order a reader needs it (Felipe 2026-10-01: simple,
 * organized, product copy like Stripe, Cloudflare and Supabase): status,
 * four numbers, the map, then the issues. Detail lives one click away.
 */
export default async function Overview() {
  const { userId } = await requireDashboardSession();
  const [findings, runs, repos, reviews, attackTasks, live] = await Promise.all([
    getOpenFindings(userId),
    getRuns(userId, 5),
    getRepositories(userId),
    getRecentPullRequestReviews(userId).catch(() => []),
    getAttackTasks(userId).catch(() => null),
    loadLiveReach(userId).catch(() => null),
  ]);
  // A3: the attack's real state in one line; unreadable shows nothing.
  const attack = attackTasks ? attackFeed(attackTasks) : null;

  if (repos.length === 0) {
    return (
      <div className="v3-empty">
        <p style={{ fontSize: 16 }}>No repository connected.</p>
        <p className="v3-small" style={{ marginTop: 8 }}>Connect GitHub and select a repository to run your first audit.</p>
        <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 18 }}>Get started</Link>
      </div>
    );
  }

  // The status reads the newest FINISHED audit; one in progress is shown as
  // in progress, never as a clean run with nothing read yet.
  const { current, finished: latest } = auditState(runs);
  const { map, mapRepo, hot } = await loadOverviewMap({ userId, runs, latest, repos, findings });
  // Severity first, then routes real traffic is hitting hard (cross-layer).
  const ordered = withTraffic(findings, hot);
  const { routes: routeCount, exposed } = mapCounts(map);
  const blocked = reviews.filter((r) => r.verdict === "block").length;
  // Live addresses with no route in the audited repository count as one more
  // area not checked (lib/chain/shadowRoutes.ts), as on Coverage.
  const boundName = live ? repos.find((r) => r.id === live.repositoryId)?.fullName : undefined;
  const unread = latest ? notCheckedAreas(latest.coverage,
    boundName === latest.fullName ? shadowRoutesFromRuns(live, runs, latest.fullName, repos.map((r) => r.fullName)) : { state: "unknown", why: "" }) : 0;
  // Only confirmed issues set the status (A1, Felipe 2026-10-07: prioritize
  // accuracy); candidates are named as "to review", never counted as issues.
  const issues = findings.filter((f) => f.confirmed);
  const toReview = findings.filter((f) => !f.confirmed).length;
  const verdict = verdictOf({ audited: Boolean(latest), lastRunFailed: latest?.status === "failed", findings: issues, unread, blockedPrs: blocked, toReview });

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">
            {current ? <>{current.fullName} · Audit {current.status === "queued" ? "queued" : "running now"}</>
              : latest ? <>{latest.fullName} · Last audit <When at={latest.startedAt} /></> : repos[0].fullName}
          </p>
          <h1>Overview</h1>
        </div>
        <RunAuditButton repository={mapRepo.fullName} />
      </div>

      <div className="v3-stack">
        <LiveRefresh active={current !== null || attack?.phase === "waiting_for_agent" || attack?.phase === "checking"} />
        <Verdict
          verdict={verdict}
          action={findings.length > 0
            ? <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-primary">{issues.length > 0 ? "View issues" : "Review candidates"}</Link>
            : unread > 0 ? <Link href="/dashboard/coverage" className="v3-btn v3-btn-sm v3-ondark">View coverage</Link> : null}
        />

        {attack ? <AttackSummary feed={attack} /> : null}

        <div className="v3-metrics">
          <Metric label="Open issues" value={issues.length} href="/dashboard/risks" link={toReview > 0 ? `${toReview} to review` : "View issues"} tone="crit" />
          <Metric label="Exposed routes" value={exposed} href="#map" link={`of ${routeCount} routes`} tone="crit" />
          <Metric label="Blocked pull requests" value={blocked} href="/dashboard/prs" link={`${reviews.length} checked`} tone="warn" />
          <Metric label="Not checked" value={unread} href="/dashboard/coverage" link="View coverage" tone="warn" />
        </div>

        <section id="map" aria-labelledby="map-title">
          <div className="v3-between" style={{ marginBottom: 10 }}>
            <h2 id="map-title" className="v3-eyebrow">Map</h2>
            {map ? <span className="v3-small">Select a route to simulate a request.</span> : null}
          </div>
          {map ? <RouteMap map={map} /> : (
            <div className="v3-empty">
              <p>{latest ? "Your map appears after the next audit." : "Run an audit to see your map."}</p>
              <p className="v3-small" style={{ marginTop: 6 }}>Routes, the checks they pass, and the data they reach.</p>
            </div>
          )}
        </section>

        <section className="v3-card" aria-labelledby="issues-title">
          <div className="v3-hd">
            <h2 id="issues-title" className="v3-eyebrow">Issues</h2>
            {findings.length > 0 ? <Link href="/dashboard/risks" className="v3-small">View all</Link> : null}
          </div>
          {findings.length === 0 ? (
            <p className="v3-card-p v3-small">{latest ? "No open issues or candidates in the code this audit read." : "No audits yet."}</p>
          ) : (
            <table className="v3-issues">
              <thead>
                <tr><th>Severity</th><th>Issue</th><th className="hide-sm">Route</th><th className="hide-sm">Status</th></tr>
              </thead>
              <tbody>
                {ordered.slice(0, 6).map((f) => (
                  <tr key={f.rowId}>
                    <td><Sev severity={f.severity} /></td>
                    <td><Link href="/dashboard/risks">{f.title}</Link>{f.hitHard ? <> <HitHard hit={f.hitHard} /></> : null}</td>
                    <td className="hide-sm route">{f.entry ?? f.file ?? ""}</td>
                    <td className="hide-sm">
                      {f.fixPrUrl ? <a href={f.fixPrUrl} target="_blank" rel="noreferrer" className="v3-tag ok">PR #{f.fixPrNumber}</a>
                        : <span className={f.confirmed ? "v3-tag crit" : "v3-tag"}>{f.confirmed ? "Confirmed" : "To review"}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </>
  );
}

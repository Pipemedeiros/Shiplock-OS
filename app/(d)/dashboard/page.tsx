import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { Sev } from "@/components/v3/FindingParts";
import { RunAuditButton } from "@/components/v3/RunAuditButton";
import { RouteMap } from "@/components/v3/RouteMap";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { getHotRoutes, type HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { buildRouteMap } from "@/lib/routeMap";
import { When } from "@/components/v3/When";
import { Metric, Verdict } from "@/components/v3/Verdict";
import { verdictOf } from "@/lib/verdict";
import { getRecentPullRequestReviews } from "@/lib/agent/pullRequestReviews";

export const metadata = { title: "Overview" };

/**
 * Overview, in the order a reader needs it (Felipe 2026-10-01: simple,
 * organized, product copy like Stripe, Cloudflare and Supabase): status,
 * four numbers, the map, then the issues. Detail lives one click away.
 */
export default async function Overview() {
  const { userId } = await requireDashboardSession();
  const [findings, runs, repos, reviews] = await Promise.all([
    getOpenFindings(userId),
    getRuns(userId, 5),
    getRepositories(userId),
    getRecentPullRequestReviews(userId).catch(() => []),
  ]);

  if (repos.length === 0) {
    return (
      <div className="v3-empty">
        <p style={{ fontSize: 16 }}>No repository connected.</p>
        <p className="v3-small" style={{ marginTop: 8 }}>Connect GitHub and select a repository to run your first audit.</p>
        <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 18 }}>Get started</Link>
      </div>
    );
  }

  const latest = runs[0];
  // Q27: the map is built from the last audit's stored route facts; the
  // source snapshot is read only when an older run has none.
  const mapRepo = repos.find((r) => r.fullName === latest?.fullName) ?? repos[0];
  const auditRoutes = runs.find((r) => r.fullName === mapRepo.fullName && r.routeFacts)?.routeFacts ?? null;
  const noHot: Record<string, HotRouteOffer[]> = {};
  const [source, hot] = latest
    ? await Promise.all([auditRoutes ? null : loadRepositoryGraphSource(userId, mapRepo.id), getHotRoutes(userId).catch(() => noHot)])
    : [null, noHot];
  const mapRoutes = auditRoutes ?? (source?.routes?.length ? source.routes : null);
  const map = mapRoutes
    ? buildRouteMap({
        routes: mapRoutes,
        tools: latest?.stack?.tools ?? [],
        findings: findings.filter((f) => f.repositoryId === mapRepo.id),
        hotFiles: (hot[mapRepo.id] ?? []).map((h) => h.file),
      })
    : null;

  const routes = map?.nodes.filter((n) => n.kind === "route") ?? [];
  const exposed = routes.filter((n) => n.exposure === "open" || n.exposure === "unscoped").length;
  const blocked = reviews.filter((r) => r.verdict === "block").length;
  const unread = latest?.coverage.length ?? 0;
  const verdict = verdictOf({ audited: Boolean(latest), lastRunFailed: latest?.status === "failed", findings, unread, blockedPrs: blocked });

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">
            {latest ? <>{latest.fullName} · Last audit <When at={latest.startedAt} /></> : repos[0].fullName}
          </p>
          <h1>Overview</h1>
        </div>
        <RunAuditButton repository={mapRepo.fullName} />
      </div>

      <div className="v3-stack">
        <Verdict
          verdict={verdict}
          action={findings.length > 0
            ? <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-primary">View issues</Link>
            : unread > 0 ? <Link href="/dashboard/coverage" className="v3-btn v3-btn-sm v3-ondark">View coverage</Link> : null}
        />

        <div className="v3-metrics">
          <Metric label="Open issues" value={findings.length} href="/dashboard/risks" link="View issues" tone="crit" />
          <Metric label="Exposed routes" value={exposed} href="#map" link={`of ${routes.length} routes`} tone="crit" />
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
            <p className="v3-card-p v3-small">{latest ? "No open issues in the code this audit read." : "No audits yet."}</p>
          ) : (
            <table className="v3-issues">
              <thead>
                <tr><th>Severity</th><th>Issue</th><th className="hide-sm">Route</th><th className="hide-sm">Status</th></tr>
              </thead>
              <tbody>
                {findings.slice(0, 6).map((f) => (
                  <tr key={f.rowId}>
                    <td><Sev severity={f.severity} /></td>
                    <td><Link href="/dashboard/risks">{f.title}</Link></td>
                    <td className="hide-sm route">{f.entry ?? f.file ?? ""}</td>
                    <td className="hide-sm">
                      {f.fixPrUrl ? <a href={f.fixPrUrl} target="_blank" rel="noreferrer" className="v3-tag ok">PR #{f.fixPrNumber}</a>
                        : <span className="v3-tag">Open</span>}
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

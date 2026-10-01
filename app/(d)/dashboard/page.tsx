import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings, getRecentlyClosed, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { Chain, Claims, Conf, Sev } from "@/components/v3/FindingParts";
import { RunAuditButton } from "@/components/v3/RunAuditButton";
import { RouteMap } from "@/components/v3/RouteMap";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { getHotRoutes, type HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { buildRouteMap } from "@/lib/routeMap";
import { When } from "@/components/v3/When";
import { Verdict } from "@/components/v3/Verdict";
import { verdictOf } from "@/lib/verdict";
import { getRecentPullRequestReviews } from "@/lib/agent/pullRequestReviews";

export const metadata = { title: "Overview" };

export default async function Overview() {
  const { userId } = await requireDashboardSession();
  const [findings, runs, repos, closed, reviews] = await Promise.all([
    getOpenFindings(userId),
    getRuns(userId, 5),
    getRepositories(userId),
    getRecentlyClosed(userId),
    getRecentPullRequestReviews(userId).catch(() => []),
  ]);

  const lead = findings[0];
  const latest = runs[0];
  const waiting = findings.filter((f) => f.fixKind === "pr");

  // Q27: the map is built only from the last audit's stored route facts.
  const mapRepo = repos.find((r) => r.fullName === latest?.fullName) ?? repos[0];
  const noHot: Record<string, HotRouteOffer[]> = {};
  const [source, hot] = mapRepo && latest
    ? await Promise.all([loadRepositoryGraphSource(userId, mapRepo.id), getHotRoutes(userId).catch(() => noHot)])
    : [null, noHot];
  // Prefer the full audit's stored facts; fall back to the source snapshot.
  const auditRoutes = runs.find((r) => r.fullName === mapRepo?.fullName && r.routeFacts)?.routeFacts ?? null;
  const mapRoutes = auditRoutes ?? (source?.routes?.length ? source.routes : null);
  const map = mapRoutes
    ? buildRouteMap({
        routes: mapRoutes,
        tools: latest?.stack?.tools ?? [],
        findings: findings.filter((f) => f.repositoryId === mapRepo.id),
        hotFiles: (hot[mapRepo.id] ?? []).map((h) => h.file),
      })
    : null;

  const routeNodes = map?.nodes.filter((n) => n.kind === "route") ?? [];
  const routeCount = routeNodes.length;
  const openRoutes = routeNodes.filter((n) => n.exposure === "open").length;
  const unscopedRoutes = routeNodes.filter((n) => n.exposure === "unscoped").length;
  const exposedRoutes = openRoutes + unscopedRoutes;
  const blockedPrs = reviews.filter((r) => r.verdict === "block").length;
  const unread = latest?.coverage.length ?? 0;
  const verdict = verdictOf({ audited: Boolean(latest), lastRunFailed: latest?.status === "failed", findings, unread, blockedPrs });

  if (repos.length === 0) {
    return (
      <div className="v3-empty">
        <p style={{ fontSize: 16 }}>No repository connected yet.</p>
        <p className="v3-small" style={{ marginTop: 8 }}>
          Connect GitHub and pick a repository to run the first audit.
        </p>
        <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 18 }}>
          Get started
        </Link>
      </div>
    );
  }

  return (
    <>
      <Verdict
        verdict={verdict}
        context={latest
          ? <>{latest.fullName} · audited <When at={latest.startedAt} /></>
          : `${repos[0].fullName} · not audited yet`}
        action={
          verdict.level === "exposed" || verdict.level === "at_risk" ? (
            <>
              <Link href="/dashboard/risks" className="v3-btn v3-primary">Show me the fix</Link>
              <RunAuditButton repository={repos[0].fullName} secondary />
            </>
          ) : verdict.level === "nothing_open" ? (
            <>
              <RunAuditButton repository={repos[0].fullName} />
              <Link href="/dashboard/coverage" className="v3-btn v3-btn-sm v3-ondark">What was not read</Link>
            </>
          ) : <RunAuditButton repository={repos[0].fullName} />
        }
        layers={[
          { href: "/dashboard/risks", label: "Ways in", value: String(exposedRoutes), tone: exposedRoutes ? "crit" : "muted",
            plain: exposedRoutes ? "routes that reach data without the right check" : "no route reaches data without a check",
            engineer: `${routeCount} routes read · ${openRoutes} no sign in · ${unscopedRoutes} not scoped to the caller` },
          { href: "/dashboard/prs", label: "Pull requests", value: String(blockedPrs), tone: blockedPrs ? "warn" : "muted",
            plain: reviews.length ? `blocked out of ${reviews.length} checked` : "checked automatically once opened",
            engineer: `${reviews.filter((r) => r.verdict === "block").length} block · ${reviews.filter((r) => r.verdict === "warn").length} warn · ${reviews.filter((r) => !r.coverageComplete).length} partial` },
          { href: "/dashboard/coverage", label: "Not read", value: String(unread), tone: unread ? "warn" : "muted",
            plain: unread ? "areas the audit could not see, so no answer there" : "every area this audit covers was read",
            engineer: latest?.coverage.map((c) => c.name).join(" · ") || "no coverage notes" },
        ]}
      />

      <div className="v3-stack">
        <section aria-labelledby="route-map">
          <div className="v3-between" style={{ marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
            <h2 id="route-map" className="v3-eyebrow">Your app, as the audit read it</h2>
            {map ? (
              <span className="v3-small">
                {map.nodes.filter((n) => n.kind === "route").length} routes, the code they share and the {map.nodes.filter((n) => n.kind === "table").length} tables they reach. Pick a route and send a request.
              </span>
            ) : null}
          </div>
          {map ? <RouteMap map={map} /> : (
            <div className="v3-empty">
              <p>{latest ? "The next audit draws your map." : "Run the first audit to draw your map."}</p>
              <p className="v3-small" style={{ marginTop: 6 }}>Every route, the code they share and the data they reach, from your repository.</p>
            </div>
          )}
        </section>

        {lead ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Deal with this first</h2>
              <div className="v3-row">
                <Sev severity={lead.severity} />
                <Conf confidence={lead.confidence} />
              </div>
            </div>
            <div className="v3-card-p">
              <h3 className="v3-serif" style={{ fontSize: 21 }}>{lead.title}</h3>
              <p className="v3-sub" style={{ marginTop: 8, maxWidth: 700 }}>{lead.consequence}</p>
              <details className="v3-proof" style={{ marginTop: 12 }}>
                <summary>Show the proof</summary>
                {lead.entry ? <Chain entry={lead.entry} file={lead.file} blastRadius={lead.blastRadius} /> : null}
                <Claims claims={lead.claims} />
              </details>
              <div className="v3-row" style={{ marginTop: 18 }}>
                <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-primary">Open the evidence</Link>
                {lead.fixPrUrl ? (
                  <a href={lead.fixPrUrl} className="v3-btn v3-btn-sm v3-ghost" target="_blank" rel="noreferrer">
                    Pull request #{lead.fixPrNumber} is open
                  </a>
                ) : null}
              </div>
            </div>
          </div>
        ) : latest ? (
          <div className="v3-empty">
            <p>Nothing we found is still open.</p>
            <p className="v3-small" style={{ marginTop: 6 }}>
              That is not the same as nothing being wrong. See Coverage for what this audit did not reach.
            </p>
          </div>
        ) : null}


        <div className="v3-grid-2">
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Waiting on you</h2>
              <span className="v3-small">{waiting.length} to approve</span>
            </div>
            <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 13 }}>
              {waiting.length === 0 ? (
                <p className="v3-small">Nothing is waiting for approval.</p>
              ) : (
                waiting.slice(0, 4).map((f) => (
                  <div key={f.rowId} className="v3-between" style={{ alignItems: "flex-start" }}>
                    <div>
                      <b style={{ fontWeight: 500, fontSize: 14 }}>{f.title}</b>
                      <p className="v3-small" style={{ marginTop: 3 }}>
                        {f.fixPrUrl ? `Pull request #${f.fixPrNumber} open` : "A fix can be prepared for this"}
                      </p>
                    </div>
                    <Sev severity={f.severity} />
                  </div>
                ))
              )}
              <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }}>
                All risks
              </Link>
            </div>
          </div>

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Since your last look</h2>
              <Link href="/dashboard/activity" className="v3-small">All activity</Link>
            </div>
            <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 13 }}>
              {runs.slice(0, 3).map((run) => (
                <div key={run.id} className="v3-between" style={{ alignItems: "flex-start" }}>
                  <div className="v3-row" style={{ gap: 10, alignItems: "flex-start", flexWrap: "nowrap" }}>
                    <i
                      className="v3-dot"
                      style={{
                        marginTop: 7,
                        background: run.status === "failed" ? "var(--crit)" : run.findingsCount > 0 ? "var(--warn)" : "var(--muted-2)",
                      }}
                    />
                    <span>
                      <b style={{ fontWeight: 500, fontSize: 14 }}>
                        {run.status === "failed" ? "Audit stopped" : `Audit of ${run.fullName}`}
                      </b>
                      <small style={{ display: "block", color: "var(--muted)", fontSize: 12.5 }}>
                        {run.status === "failed"
                          ? run.error ?? "no reason recorded"
                          : `${run.entriesFound ?? 0} entries · ${run.findingsCount} ${run.findingsCount === 1 ? "finding" : "findings"}`}
                      </small>
                    </span>
                  </div>
                  <span className="v3-small" style={{ whiteSpace: "nowrap" }}>
                    <When at={run.startedAt} date />
                  </span>
                </div>
              ))}
              {closed.length > 0 ? (
                <p className="v3-small" style={{ borderTop: "1px solid var(--line-2)", paddingTop: 11 }}>
                  {closed.length} closed in the last 30 days.
                </p>
              ) : null}
            </div>
          </div>
        </div>

      </div>
    </>
  );
}

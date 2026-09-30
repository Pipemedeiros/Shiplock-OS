import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings, getRecentlyClosed, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { Chain, Conf, Sev } from "@/components/v3/FindingParts";
import { RunAuditButton } from "@/components/v3/RunAuditButton";
import { RouteMap } from "@/components/v3/RouteMap";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { getHotRoutes, type HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { buildRouteMap } from "@/lib/routeMap";

export const metadata = { title: "Overview" };

export default async function Overview() {
  const { userId } = await requireDashboardSession();
  const [findings, runs, repos, closed] = await Promise.all([
    getOpenFindings(userId),
    getRuns(userId, 5),
    getRepositories(userId),
    getRecentlyClosed(userId),
  ]);

  const criticals = findings.filter((f) => f.severity === "CRITICAL");
  const lead = findings[0];
  const latest = runs[0];
  const waiting = findings.filter((f) => f.fixKind === "pr");

  // Q27: the map is built only from the last audit's stored route facts.
  const mapRepo = repos.find((r) => r.fullName === latest?.fullName) ?? repos[0];
  const noHot: Record<string, HotRouteOffer[]> = {};
  const [source, hot] = mapRepo && latest
    ? await Promise.all([loadRepositoryGraphSource(userId, mapRepo.id), getHotRoutes(userId).catch(() => noHot)])
    : [null, noHot];
  const map = source?.routes?.length
    ? buildRouteMap({
        routes: source.routes,
        tools: latest?.stack?.tools ?? [],
        findings: findings.filter((f) => f.repositoryId === mapRepo.id),
        hotFiles: (hot[mapRepo.id] ?? []).map((h) => h.file),
      })
    : null;

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
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">
            {latest
              ? `${latest.fullName} · audited ${new Date(latest.startedAt).toLocaleString()}`
              : `${repos[0].fullName} · not audited yet`}
          </p>
          <h1 className="v3-serif">
            {criticals.length > 0
              ? `${criticals.length} ${criticals.length === 1 ? "path" : "paths"} reach customer data.`
              : findings.length > 0
                ? `${findings.length} open ${findings.length === 1 ? "finding" : "findings"}.`
                : latest
                  ? "Nothing open."
                  : "Ready for the first audit."}
          </h1>
        </div>
        <RunAuditButton repository={repos[0].fullName} />
      </div>

      <div className="v3-stack">
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
              {lead.entry ? <Chain entry={lead.entry} file={lead.file} blastRadius={lead.blastRadius} /> : null}
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

        {map ? (
          <section aria-labelledby="route-map">
            <div className="v3-between" style={{ marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
              <h2 id="route-map" className="v3-eyebrow">Route map</h2>
              <span className="v3-small">
                {map.nodes.filter((n) => n.kind === "route").length} routes and {map.nodes.filter((n) => n.kind === "table").length} tables from the last audit. Drag to turn it.
              </span>
            </div>
            <RouteMap map={map} />
          </section>
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
                    {new Date(run.startedAt).toLocaleDateString()}
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

        {latest && latest.coverage.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">What this audit did not cover</h2>
              <Link href="/dashboard/coverage" className="v3-small">Coverage</Link>
            </div>
            <div className="v3-card-p">
              <div className="v3-row" style={{ gap: 8 }}>
                {latest.coverage.map((c) => <span key={c.name} className="v3-tag">{c.name}</span>)}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}

import Link from "next/link";
import { RouteMap } from "./RouteMap";
import { Metric } from "./Verdict";
import { Sev } from "./FindingParts";
import { When } from "./When";
import { withSources, type RouteMap as RouteMapData } from "@/lib/routeMap";
import type { TrafficPulse } from "@/lib/traffic/pulse";
import type { AttackView, Outcome } from "@/lib/traffic/attackView";

/**
 * The Traffic page (Felipe 2026-10-16: see traffic, the routes under attack,
 * the graph, and who attacked them). Built from what the snippet already
 * sends and what detection logged; a source is a short alias of its salted
 * hash. An attempt is shown as an attempt; how the app answered is shown
 * only where the snippet reports it (lib/traffic/attackView.ts routeOutcome),
 * and nothing here says a route was breached. Not connected and unreadable
 * are said as such, never as a quiet page.
 */
export type TrafficViewProps = {
  repository: string; sites: number; installed: boolean; lastSeenAt: string | null;
  pulse: TrafficPulse; view: AttackView | null; map: RouteMapData | null; capped: boolean;
};

/** A path that wraps only after a slash, never mid word. */
function Path({ path }: { path: string }) {
  const parts = path.split("/");
  return <>{parts.map((part, i) => <span key={i}>{i > 0 ? "/" : ""}{part}{i < parts.length - 1 ? <wbr /> : null}</span>)}</>;
}

const OUTCOME_LABEL: Record<Outcome["kind"], { label: string; tone: string }> = {
  worked: { label: "Probably worked", tone: " crit" },
  errored: { label: "App errored", tone: " warn" },
  answered: { label: "Answered", tone: "" },
  refused: { label: "Refused", tone: "" },
  unreported: { label: "Not reported", tone: "" },
};

function Answer({ outcome }: { outcome: Outcome }) {
  const o = OUTCOME_LABEL[outcome.kind];
  return <><span className={`v3-tag${o.tone}`}>{o.label}</span><br /><span className="v3-small">{outcome.detail}</span></>;
}

function Volume({ pulse }: { pulse: TrafficPulse }) {
  const max = Math.max(1, ...pulse.buckets);
  const peak = Math.max(...pulse.buckets);
  const w = 100 / pulse.buckets.length;
  return (
    <svg className="v3-traffic-bars" viewBox="0 0 100 40" preserveAspectRatio="none" role="img"
      aria-label={`Requests per 2 hours over the last ${pulse.windowHours} hours: ${pulse.watched} in total, at most ${peak} in one interval.`}>
      {pulse.buckets.map((n, i) => {
        const h = n === 0 ? 0.6 : Math.max(1.5, (n / max) * 38);
        return <rect key={i} x={i * w + w * 0.15} y={40 - h} width={w * 0.7} height={h} rx={0.6} />;
      })}
    </svg>
  );
}

function StatusLine({ sites, installed, lastSeenAt }: Pick<TrafficViewProps, "sites" | "installed" | "lastSeenAt">) {
  if (!installed) {
    return (
      <p className="v3-card-p">
        <span className="v3-dot" /> No request in the last 24 hours. The snippet may not be deployed, or your app had no visitors.
        {lastSeenAt ? <> Last request <When at={lastSeenAt} />.</> : null}
      </p>
    );
  }
  return (
    <p className="v3-card-p">
      <span className="v3-dot live" /> Watching {sites} {sites === 1 ? "site" : "sites"}.
      {lastSeenAt ? <> Last request <When at={lastSeenAt} />.</> : null}
    </p>
  );
}

export function TrafficView(props: TrafficViewProps) {
  const { repository, sites, installed, lastSeenAt, pulse, view, map, capped } = props;

  if (sites === 0) {
    return (
      <>
        <div className="v3-page-hd"><div><p className="v3-eyebrow">{repository}</p><h1>Traffic</h1></div></div>
        <div className="v3-empty">
          <p style={{ fontSize: 16 }}>Traffic is not connected.</p>
          <p className="v3-small" style={{ marginTop: 8 }}>
            Add the snippet to your app to see who requests your routes, which ones are attacked, and by whom. It sends ShipLock the path and a salted visitor hash, never a body or a password.
          </p>
          <Link href="/dashboard/settings" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 18 }}>Connect traffic</Link>
        </div>
      </>
    );
  }

  const shownMap = map && view ? withSources(map, view.attackers) : map;
  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">{repository} · Last {pulse.windowHours} hours</p>
          <h1>Traffic</h1>
        </div>
      </div>

      <div className="v3-stack">
        <section className="v3-card" aria-label="Traffic status">
          <StatusLine sites={sites} installed={installed} lastSeenAt={lastSeenAt} />
        </section>

        {view ? (
          <div className="v3-metrics">
            <Metric label="Requests watched" value={pulse.watched} href="#volume" link={`${pulse.sources} visitors`} />
            <Metric label="Flagged sources" value={view.totals.attackers} href="#sources" link={`${view.totals.blocked} blocked`} tone="warn" />
            <Metric label="Attacked routes" value={view.totals.attackedRoutes} href="#routes" tone="crit"
              link={view.totals.probablyWorked > 0 ? `${view.totals.probablyWorked} probably worked` : `${view.totals.attackedWithIssue} with an open issue`} />
            <Metric label="Turned away" value={pulse.turnedAway} href="#sources" link="from blocked sources" />
          </div>
        ) : (
          <section className="v3-card"><p className="v3-card-p">The attack log could not be read just now, so flagged sources and attacked routes are unknown. Reload to try again.</p></section>
        )}

        <section id="volume" className="v3-card" aria-labelledby="volume-title">
          <div className="v3-hd"><h2 id="volume-title" className="v3-eyebrow">Requests</h2><span className="v3-small">every 2 hours</span></div>
          <div className="v3-card-p">
            {pulse.hasData ? <Volume pulse={pulse} /> : <p className="v3-small">No request recorded in this window.</p>}
          </div>
        </section>

        <section id="map" aria-labelledby="attack-map-title">
          <div className="v3-between" style={{ marginBottom: 10 }}>
            <h2 id="attack-map-title" className="v3-eyebrow">Who attacked what</h2>
            <span className="v3-small">Attempts. Whether one worked shows below, where your snippet reports answers.</span>
          </div>
          {shownMap ? <RouteMap map={shownMap} /> : (
            <div className="v3-empty"><p>The map appears after your first audit.</p></div>
          )}
        </section>

        {view ? (
          <>
            <section id="routes" className="v3-card" aria-labelledby="routes-title">
              <div className="v3-hd"><h2 id="routes-title" className="v3-eyebrow">Attacked routes</h2></div>
              {view.attackedRoutes.length === 0 ? (
                <p className="v3-card-p v3-small">No flagged source requested a route from your last audit in this window.</p>
              ) : (
                <table className="v3-issues">
                  <thead><tr><th>Route</th><th>Requests</th><th className="hide-sm">Sources</th><th>Open issue</th><th>Answer</th></tr></thead>
                  <tbody>
                    {view.attackedRoutes.map((r) => (
                      <tr key={r.file}>
                        <td className="route"><Path path={r.pattern} /></td>
                        <td>{r.requests}</td>
                        <td className="hide-sm">{r.attackers}</td>
                        <td>
                          {r.finding ? (
                            <>
                              <Sev severity={r.finding.severity} /> <Link href="/dashboard/risks">{r.finding.title}</Link>{" "}
                              <span className={`v3-tag${r.finding.confirmed ? " crit" : ""}`}>{r.finding.confirmed ? "Confirmed" : "To review"}</span>
                            </>
                          ) : <span className="v3-small">None read in the code</span>}
                        </td>
                        <td><Answer outcome={r.outcome} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>

            <section id="sources" className="v3-card" aria-labelledby="sources-title">
              <div className="v3-hd"><h2 id="sources-title" className="v3-eyebrow">Flagged sources</h2></div>
              {view.attackers.length === 0 ? (
                <p className="v3-card-p v3-small">Detection flagged no source in this window. It flags brute force, scanners, floods, attack probes and record id walks.</p>
              ) : (
                <table className="v3-issues">
                  <thead><tr><th>Source</th><th>What it did</th><th className="hide-sm">Routes hit</th><th className="hide-sm">Last seen</th><th>Status</th></tr></thead>
                  <tbody>
                    {view.attackers.map((a) => (
                      <tr key={a.sourceId}>
                        <td className="route">{a.alias}</td>
                        <td>{a.kinds.join(", ")}<br /><span className="v3-small">{a.requests} {a.requests === 1 ? "request" : "requests"}</span></td>
                        <td className="hide-sm route">
                          {a.routes.length ? a.routes.map((r) => `${r.pattern} (${r.requests})`).join(", ") : "None on your routes"}
                          {a.unmatchedPaths ? <><br /><span className="v3-small">{a.unmatchedPaths} {a.unmatchedPaths === 1 ? "path that matches" : "paths that match"} no route</span></> : null}
                        </td>
                        <td className="hide-sm"><When at={a.lastSeen} /></td>
                        <td>
                          {a.status === "blocked" && a.blockedUntil
                            ? <span className="v3-tag crit">Blocked until <When at={a.blockedUntil} /></span>
                            : <span className="v3-tag warn">Flagged</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {capped ? <p className="v3-card-p v3-small">Showing the most recent activity; older entries in this window were not read.</p> : null}
            </section>
          </>
        ) : null}

        {pulse.recentPaths.length > 0 ? (
          <section className="v3-card" aria-labelledby="latest-title">
            <div className="v3-hd"><h2 id="latest-title" className="v3-eyebrow">Latest requests</h2></div>
            <ul className="v3-card-p v3-traffic-latest">
              {pulse.recentPaths.map((p, i) => (
                <li key={`${p.path}-${i}`}>
                  <span className="v3-code-tag">{p.method}</span> <span className="route">{p.path}</span>
                  {p.blocked ? <> <span className="v3-tag crit">Turned away</span></> : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </div>
    </>
  );
}

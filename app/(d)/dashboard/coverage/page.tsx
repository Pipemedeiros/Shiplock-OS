import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getRuns } from "@/lib/agent/dashboardData";

/**
 * What the last audit did not reach.
 *
 * This page exists because absent is not the same as clean. A tool that only
 * ever reports what it found lets a thinner audit look like a better one, and
 * the customer has no way to tell the difference. Every note here is generated
 * from what actually happened in the run.
 */
export default async function Coverage() {
  const { userId } = await requireDashboardSession();
  const runs = await getRuns(userId, 1);
  const latest = runs[0];

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">What we read, and what we did not</p>
          <h1 className="v3-serif">Coverage</h1>
        </div>
      </div>

      {!latest ? (
        <div className="v3-empty">
          <p>No audit has run yet.</p>
          <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 16 }}>
            Run the first audit
          </Link>
        </div>
      ) : (
        <div className="v3-stack">
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Read in the last audit</h2>
              <span className="v3-small">{new Date(latest.startedAt).toLocaleString()}</span>
            </div>
            <div className="v3-card-p v3-grid-3">
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.filesRead ?? 0}</p>
                <p className="v3-small">files</p>
              </div>
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.entriesFound ?? 0}</p>
                <p className="v3-small">application entries</p>
              </div>
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.tablesFound ?? 0}</p>
                <p className="v3-small">tables</p>
              </div>
            </div>
          </div>

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Not covered</h2>
              <span className="v3-small">And what would change it</span>
            </div>
            <div className="v3-card-p v3-cov">
              {latest.coverage.length === 0 ? (
                <p className="v3-small">No gaps were recorded for this run.</p>
              ) : (
                latest.coverage.map((c) => (
                  <div key={c.name}>
                    <b>{c.name}</b>
                    <span style={{ fontSize: 14, color: "var(--muted)" }}>
                      {c.why}
                      <small style={{ display: "block", marginTop: 5, fontFamily: "inherit", fontSize: 13 }}>
                        {c.effect}
                      </small>
                    </span>
                    {c.upgrade ? (
                      <Link href="/dashboard/settings" className="v3-btn v3-btn-sm v3-ghost">{c.upgrade}</Link>
                    ) : (
                      <span className="v3-small">Nothing to connect</span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="v3-card v3-card-p">
            <p className="v3-sub" style={{ fontSize: 14, maxWidth: 720 }}>
              Connecting a database raises findings from inferred to proven, because a policy can then
              be reproduced on a disposable copy of your schema rather than read from code alone. It is
              not a setup step and nothing is withheld without it.
            </p>
          </div>
        </div>
      )}
    </>
  );
}

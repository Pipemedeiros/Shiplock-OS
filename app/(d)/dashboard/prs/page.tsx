import Link from "next/link";
import { GitPullRequest, ArrowUpRight } from "lucide-react";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { Sev } from "@/components/v3/FindingParts";

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
  const findings = await getOpenFindings(userId);

  const open = findings.filter((f) => f.fixPrUrl);
  const eligible = findings.filter((f) => !f.fixPrUrl && f.fixKind === "pr");
  const manual = findings.filter((f) => !f.fixPrUrl && f.fixKind !== "pr");

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">Opened by ShipLock, waiting on you</p>
          <h1 className="v3-serif">Pull requests</h1>
          <p className="v3-sub" style={{ marginTop: 8, maxWidth: 620 }}>
            Each one is a branch of its own, off your default branch. We never merge, and we never
            push to your default branch — approving is yours.
          </p>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Open</h2>
            <span className="v3-small">{open.length} waiting for approval</span>
          </div>
          <div className="v3-card-p">
            {open.length === 0 ? (
              <p className="v3-small">
                Nothing is waiting. When an audit finds something with a mechanical fix, the pull
                request is opened here automatically.
              </p>
            ) : (
              <div className="v3-list">
                {open.map((f) => (
                  <a
                    key={f.rowId}
                    href={f.fixPrUrl as string}
                    target="_blank"
                    rel="noreferrer"
                    className="v3-pr-row"
                  >
                    <GitPullRequest size={16} className="v3-pr-icon" />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="v3-between">
                        <b style={{ fontWeight: 500, fontSize: 14 }}>{f.title}</b>
                        <Sev severity={f.severity} />
                      </div>
                      <p className="v3-small" style={{ marginTop: 3 }}>
                        #{f.fixPrNumber ?? "?"} · {f.repository}
                        {f.entry ? ` · ${f.entry}` : ""}
                      </p>
                    </div>
                    <ArrowUpRight size={15} className="v3-pr-go" />
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>

        {eligible.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Being prepared</h2>
              <span className="v3-small">{eligible.length}</span>
            </div>
            <div className="v3-card-p">
              <p className="v3-small" style={{ marginBottom: 12 }}>
                These have a mechanical fix and no pull request yet — either the last audit hit its
                per-run limit, or GitHub was unreachable when it finished. The next audit opens them.
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
          </div>
        ) : null}

        {manual.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Not a pull request</h2>
              <span className="v3-small">{manual.length}</span>
            </div>
            <div className="v3-card-p">
              <p className="v3-small" style={{ marginBottom: 12 }}>
                These are decisions about your architecture rather than mechanical changes. Writing
                the patch for you would be guessing at what you meant.
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
                Read the reasoning
              </Link>
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}

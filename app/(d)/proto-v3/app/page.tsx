"use client";

import Link from "next/link";
import { ACTIVITY, PULL_REQUESTS, RESOLVED, STACK_BLIND } from "../data";
import { useStore } from "../store";
import { Chain, Conf, Eyebrow, Sev } from "../ui";

export default function Overview() {
  const { openRisks, toast } = useStore();
  const criticals = openRisks.filter((r) => r.severity === "critical");
  const lead = openRisks[0];
  const waiting = PULL_REQUESTS.filter((p) => p.state !== "clear");

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>ledgerloop/app · 4f1e9c2 · audited 11 minutes ago</Eyebrow>
          <h1 className="v3-serif">
            {criticals.length > 0
              ? `${criticals.length} ${criticals.length === 1 ? "way" : "ways"} in reach customer data.`
              : "Nothing open reaches customer data."}
          </h1>
        </div>
        <Link href="/proto-v3/app/risks" className="v3-btn v3-btn-sm v3-primary">Review risks</Link>
      </div>

      <div className="v3-stack">
        {lead ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Deal with this first</h2>
              <div className="v3-row">
                <Sev severity={lead.severity} />
                <Conf confidence={lead.confidence} />
                <span className="v3-code-tag">{lead.code}</span>
              </div>
            </div>
            <div className="v3-card-p">
              <h3 className="v3-serif" style={{ fontSize: 21 }}>{lead.title}</h3>
              <p className="v3-sub" style={{ marginTop: 8, maxWidth: 680 }}>{lead.consequence}</p>
              <Chain risk={lead} />
              <p className="v3-small" style={{ marginTop: 14 }}>
                <span className="v3-eyebrow">Blast radius</span>{" "}{lead.blastRadius}
              </p>
              <div className="v3-row" style={{ marginTop: 18 }}>
                <Link href="/proto-v3/app/risks" className="v3-btn v3-btn-sm v3-primary">Open the evidence</Link>
                <span className="v3-small">A fix is prepared and passed all three checks.</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="v3-empty">
            <p>Every path we found is closed.</p>
            <p className="v3-small" style={{ marginTop: 6 }}>
              That is not the same as “nothing is wrong” — see Coverage for what we cannot see.
            </p>
          </div>
        )}

        <div className="v3-grid-2">
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Since your last look</h2>
              <Link href="/proto-v3/app/activity" className="v3-small">All activity</Link>
            </div>
            <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {ACTIVITY.map((a) => (
                <div key={a.title} className="v3-between" style={{ alignItems: "flex-start" }}>
                  <div className="v3-row" style={{ alignItems: "flex-start", flexWrap: "nowrap", gap: 11 }}>
                    <i
                      className="v3-dot"
                      style={{
                        marginTop: 7,
                        background: a.tone === "alert" ? "var(--crit)" : a.tone === "good" ? "var(--ok)" : "var(--muted-2)",
                      }}
                    />
                    <span>
                      <b style={{ fontWeight: 500, fontSize: 14 }}>{a.title}</b>
                      <small style={{ display: "block", color: "var(--muted)", fontSize: 12.5 }}>{a.detail}</small>
                    </span>
                  </div>
                  <span className="v3-small" style={{ whiteSpace: "nowrap" }}>{a.when}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Waiting on you</h2>
              <span className="v3-small">{waiting.length} pull requests</span>
            </div>
            <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {waiting.map((p) => (
                <div key={p.number} className="v3-between" style={{ alignItems: "flex-start" }}>
                  <div>
                    <div className="v3-row" style={{ gap: 8 }}>
                      <span className="v3-code-tag">#{p.number}</span>
                      <b style={{ fontWeight: 500, fontSize: 14 }}>{p.title}</b>
                    </div>
                    <p className="v3-small" style={{ marginTop: 3 }}>{p.verdict}</p>
                  </div>
                  <span className={`v3-tag ${p.state === "blocked" ? "crit" : p.state === "warned" ? "warn" : "ok"}`}>
                    {p.state === "ours" ? "ours" : p.state}
                  </span>
                </div>
              ))}
              <Link href="/proto-v3/app/activity" className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }}>
                All pull requests
              </Link>
            </div>
          </div>
        </div>

        {/* The panel neither earlier prototype had. */}
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">What we could not see</h2>
            <Link href="/proto-v3/app/coverage" className="v3-small">Coverage</Link>
          </div>
          <div className="v3-card-p">
            <p className="v3-sub" style={{ fontSize: 14, maxWidth: 680 }}>
              A clean report is only worth what it covers. These are the parts of your system this
              audit did not reach — and what would change that.
            </p>
            <div className="v3-row" style={{ marginTop: 14, gap: 8 }}>
              {STACK_BLIND.map((b) => (
                <span key={b.name} className="v3-tag">{b.name}</span>
              ))}
            </div>
          </div>
        </div>

        <div className="v3-card v3-card-p v3-between">
          <div>
            <b style={{ fontWeight: 500 }}>An enterprise prospect asked whether you are secure.</b>
            <p className="v3-small" style={{ marginTop: 3 }}>
              Send a live posture page instead of a PDF you wrote yourself. {RESOLVED.length} findings
              closed in the last 30 days are on it.
            </p>
          </div>
          <button
            className="v3-btn v3-btn-sm v3-ghost"
            onClick={() => { navigator.clipboard?.writeText("https://shiplock.dev/verified/ledgerloop"); toast("Report link copied"); }}
          >
            Copy report link
          </button>
        </div>
      </div>
    </>
  );
}

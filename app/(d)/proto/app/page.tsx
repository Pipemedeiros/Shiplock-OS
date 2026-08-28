"use client";

import Link from "next/link";
import { PATHS, PULLS, RESOLVED } from "../data";
import { useProto } from "../store";
import { ConfTag, SevTag } from "../ui";

export default function Overview() {
  const { openPaths, statusOf, toast } = useProto();
  const criticals = openPaths.filter((p) => p.severity === "critical");
  const top = openPaths[0];

  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">ledgerloop/app · 4f1e9c2 · audited 11 minutes ago</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>
            {criticals.length > 0
              ? `${criticals.length} way${criticals.length === 1 ? "" : "s"} in that reach customer data.`
              : "Nothing open reaches customer data."}
          </h1>
        </div>
        <Link href="/proto/app/paths" className="pr-btn pr-btn-primary pr-btn-sm">Review paths</Link>
      </div>

      <div className="pr-stack">
        <div className="pr-grid-3">
          <Stat n={String(openPaths.length)} l="Paths open" />
          <Stat n={String(criticals.length)} l="Reach production data" tone="crit" />
          <Stat n={String(RESOLVED.length)} l="Closed in the last 30 days" tone="ok" />
        </div>

        {top ? (
          <div className="pr-card">
            <div className="pr-hd">
              <h3 className="pr-eyebrow">Deal with this first</h3>
              <div className="pr-row"><SevTag s={top.severity} /><ConfTag c={top.confidence} /></div>
            </div>
            <div className="pr-card-p">
              <h3 className="pr-serif" style={{ fontSize: 21 }}>{top.title}</h3>
              <p className="pr-sub" style={{ marginTop: 8 }}>{top.consequence}</p>
              <div className="pr-chain">
                {top.chain.map((n, i) => (
                  <span key={n.label} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                    {i > 0 ? <span className="pr-arrow">→</span> : null}
                    <span className={`node${n.broken ? " bad" : ""}`}>{n.label}</span>
                  </span>
                ))}
              </div>
              <div className="pr-row" style={{ marginTop: 18 }}>
                <Link href="/proto/app/paths" className="pr-btn pr-btn-primary pr-btn-sm">
                  {statusOf(top.id) === "fixing" ? "Fix PR open →" : "Open the fix"}
                </Link>
                <span className="pr-sub" style={{ fontSize: 13 }}>
                  Fix already validated on a disposable copy of your schema.
                </span>
              </div>
            </div>
          </div>
        ) : null}

        <div className="pr-grid-2">
          <div className="pr-card">
            <div className="pr-hd"><h3 className="pr-eyebrow">Since your last look</h3></div>
            <div className="pr-card-p pr-stack" style={{ gap: 12 }}>
              <Line icon="⚑" tone="crit" body="PR #431 introduces the same missing organisation scope. Merge blocked." when="12 min ago" />
              <Line icon="✓" tone="ok" body="Public read on the ll-avatars bucket closed by PR #412." when="6 days ago" />
              <Line icon="◇" tone="mute" body="Deep audit completed. No new dependencies with advisories." when="11 min ago" />
              <Line icon="◈" tone="mute" body="Two new route handlers added in ledgerloop/workers — both machine-gated." when="yesterday" />
            </div>
          </div>

          <div className="pr-card">
            <div className="pr-hd">
              <h3 className="pr-eyebrow">Waiting on you</h3>
              <span className="pr-sub" style={{ fontSize: 13 }}>{PATHS.filter((p) => p.fixKind === "pr").length} fix PRs</span>
            </div>
            <div className="pr-card-p pr-stack" style={{ gap: 12 }}>
              {PULLS.slice(0, 3).map((p) => (
                <div key={p.n} className="pr-between" style={{ alignItems: "flex-start" }}>
                  <div>
                    <div className="pr-row">
                      <span className="pr-mono" style={{ fontSize: 12.5, color: "var(--muted)" }}>#{p.n}</span>
                      <strong style={{ fontSize: 14, fontWeight: 500 }}>{p.title}</strong>
                    </div>
                    <p className="pr-sub" style={{ fontSize: 13, marginTop: 3 }}>{p.verdict}</p>
                  </div>
                  <span className={`pr-tag ${p.state === "blocked" ? "pr-tag-crit" : p.state === "warned" ? "pr-tag-warn" : p.state === "ours" ? "pr-tag-ok" : "pr-tag-mute"}`}>
                    {p.state === "ours" ? "ours" : p.state}
                  </span>
                </div>
              ))}
              <Link href="/proto/app/prs" className="pr-btn pr-btn-ghost pr-btn-sm" style={{ alignSelf: "flex-start" }}>
                All pull requests
              </Link>
            </div>
          </div>
        </div>

        <div className="pr-banner">
          <div>
            <strong>An enterprise prospect just asked whether you are secure.</strong>
            <div style={{ color: "var(--muted-navy)", fontSize: 13.5, marginTop: 4 }}>
              Send them a live posture page instead of a PDF you wrote yourself.
            </div>
          </div>
          <button className="pr-btn pr-btn-primary pr-btn-sm" onClick={() => { navigator.clipboard?.writeText("https://shiplock.dev/verified/ledgerloop"); toast("Report link copied to your clipboard"); }}>
            Copy report link
          </button>
        </div>
      </div>
    </>
  );
}

function Stat({ n, l, tone }: { n: string; l: string; tone?: "crit" | "ok" }) {
  return (
    <div className="pr-card pr-card-p">
      <div className="pr-stat-n" style={{ color: tone === "crit" ? "var(--crit)" : tone === "ok" ? "var(--ok)" : undefined }}>{n}</div>
      <div className="pr-stat-l">{l}</div>
    </div>
  );
}

function Line({ icon, body, when, tone }: { icon: string; body: string; when: string; tone: "crit" | "ok" | "mute" }) {
  const color = tone === "crit" ? "var(--crit)" : tone === "ok" ? "var(--ok)" : "var(--muted-2)";
  return (
    <div className="pr-between" style={{ alignItems: "flex-start" }}>
      <div className="pr-row" style={{ alignItems: "flex-start" }}>
        <span style={{ color }}>{icon}</span>
        <span style={{ fontSize: 14 }}>{body}</span>
      </div>
      <span className="pr-sub" style={{ fontSize: 12.5, whiteSpace: "nowrap" }}>{when}</span>
    </div>
  );
}

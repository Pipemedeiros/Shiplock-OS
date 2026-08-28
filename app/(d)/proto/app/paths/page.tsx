"use client";

import { useState } from "react";
import { PATHS, RESOLVED, type AttackPath } from "../../data";
import { useProto } from "../../store";
import { ConfTag, SevTag } from "../../ui";

export default function PathsPage() {
  const { statusOf } = useProto();
  const [open, setOpen] = useState<AttackPath | null>(null);
  const [filter, setFilter] = useState<"open" | "all">("open");

  const list = PATHS.filter((p) => (filter === "all" ? true : statusOf(p.id) !== "fixed"));

  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Attack paths</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>Ways in, ordered by what they reach.</h1>
        </div>
        <div className="pr-toggle">
          <button className={filter === "open" ? "on" : ""} onClick={() => setFilter("open")}>Open</button>
          <button className={filter === "all" ? "on" : ""} onClick={() => setFilter("all")}>All</button>
        </div>
      </div>

      <div className="pr-stack" style={{ gap: 12 }}>
        {list.map((p) => {
          const status = statusOf(p.id);
          return (
            <button key={p.id} className="pr-path" onClick={() => setOpen(p)}>
              <div className="pr-between" style={{ alignItems: "flex-start" }}>
                <div>
                  <div className="pr-row" style={{ marginBottom: 8 }}>
                    <SevTag s={p.severity} />
                    <ConfTag c={p.confidence} />
                    {status === "fixing" ? <span className="pr-tag pr-tag-warn">Fix PR open</span> : null}
                    {status === "fixed" ? <span className="pr-tag pr-tag-ok">Closed</span> : null}
                  </div>
                  <h4>{p.title}</h4>
                  <p className="pr-sub" style={{ maxWidth: 620 }}>{p.consequence}</p>
                </div>
                <span className="pr-arrow" style={{ fontSize: 20 }}>→</span>
              </div>
              <div className="pr-chain">
                {p.chain.map((n, i) => (
                  <span key={n.label} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                    {i > 0 ? <span className="pr-arrow">→</span> : null}
                    <span className={`node${n.broken ? " bad" : ""}`}>{n.label}</span>
                  </span>
                ))}
              </div>
            </button>
          );
        })}

        <div className="pr-card">
          <div className="pr-hd"><h3 className="pr-eyebrow">Closed</h3></div>
          <table className="pr-table">
            <tbody>
              {RESOLVED.map((r) => (
                <tr key={r.id}>
                  <td><span className="pr-tag pr-tag-ok">Closed</span></td>
                  <td>{r.title}</td>
                  <td className="pr-file">{r.closedBy}</td>
                  <td className="pr-sub" style={{ textAlign: "right" }}>{r.when}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {open ? <Drawer path={open} onClose={() => setOpen(null)} /> : null}
    </>
  );
}

function Drawer({ path, onClose }: { path: AttackPath; onClose: () => void }) {
  const { setStatus, statusOf, toast } = useProto();
  const [tab, setTab] = useState<"why" | "evidence" | "fix">("why");
  const status = statusOf(path.id);

  return (
    <>
      <div className="pr-drawer-bg" onClick={onClose} />
      <div className="pr-drawer">
        <div style={{ padding: "22px 26px", background: "var(--paper)", borderBottom: "1px solid var(--line)" }}>
          <div className="pr-between">
            <div className="pr-row"><SevTag s={path.severity} /><ConfTag c={path.confidence} /></div>
            <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={onClose}>Close</button>
          </div>
          <h2 className="pr-serif" style={{ fontSize: 24, margin: "14px 0 8px" }}>{path.title}</h2>
          <p className="pr-sub">{path.consequence}</p>
          <div className="pr-chain">
            {path.chain.map((n, i) => (
              <span key={n.label} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                {i > 0 ? <span className="pr-arrow">→</span> : null}
                <span className={`node${n.broken ? " bad" : ""}`} title={n.detail}>{n.label}</span>
              </span>
            ))}
          </div>
          <p className="pr-mono" style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 14 }}>
            BLAST RADIUS · {path.blastRadius}
          </p>
        </div>

        <div style={{ padding: "0 26px", background: "var(--paper)", borderBottom: "1px solid var(--line)", display: "flex", gap: 4 }}>
          {([["why", "Why we think so"], ["evidence", "Evidence"], ["fix", "The fix"]] as const).map(([k, l]) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              style={{
                background: "transparent", border: 0, padding: "12px 10px", fontSize: 13.5,
                color: tab === k ? "var(--ink)" : "var(--muted)",
                boxShadow: tab === k ? "inset 0 -2px 0 var(--bronze)" : "none",
              }}
            >
              {l}
            </button>
          ))}
        </div>

        <div style={{ padding: 26 }} className="pr-stack">
          {tab === "why" ? (
            <>
              <ol style={{ margin: 0, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 12, fontSize: 14.5 }}>
                {path.reasoning.map((r) => <li key={r}>{r}</li>)}
              </ol>
              {path.proof ? (
                <div className="pr-card pr-card-p" style={{ borderColor: "rgba(30,122,85,.4)" }}>
                  <p className="pr-eyebrow" style={{ color: "var(--ok)" }}>Reproduced</p>
                  <p style={{ marginTop: 8, fontSize: 14.5 }}>{path.proof}</p>
                </div>
              ) : (
                <div className="pr-card pr-card-p">
                  <p className="pr-eyebrow">Not reproduced</p>
                  <p className="pr-sub" style={{ marginTop: 8 }}>
                    This one is read from the code. We will not claim we proved something we did not run.
                  </p>
                </div>
              )}
            </>
          ) : null}

          {tab === "evidence" ? (
            <>
              <p className="pr-file">{path.evidenceFile}</p>
              <div className="pr-code">{path.evidence}</div>
              <button className="pr-btn pr-btn-ghost pr-btn-sm" style={{ alignSelf: "flex-start" }}
                onClick={() => toast("Opening GitHub at " + path.evidenceFile)}>
                View on GitHub
              </button>
            </>
          ) : null}

          {tab === "fix" ? (
            <>
              <h3 style={{ fontSize: 16 }}>{path.fixTitle}</h3>
              <div className="pr-code">{path.fixDiff}</div>
              {path.fixKind === "pr" ? (
                <div className="pr-card pr-card-p pr-stack" style={{ gap: 12 }}>
                  <div className="pr-between">
                    <span className="pr-eyebrow">Before we offer it</span>
                    <span className="pr-tag pr-tag-ok">3 of 3 gates passed</span>
                  </div>
                  <Gate label="The attack reproduces against your current code" ok />
                  <Gate label="With this change applied, the attack fails" ok />
                  <Gate label="With this change applied, legitimate access still works" ok />
                </div>
              ) : (
                <p className="pr-sub">
                  This one is a judgement call about your product, not a mechanical fix. We wrote the
                  suggestion; the decision is yours.
                </p>
              )}
              <div className="pr-row">
                {path.fixKind === "pr" && status === "open" ? (
                  <button className="pr-btn pr-btn-primary pr-btn-sm"
                    onClick={() => { setStatus(path.id, "fixing"); toast("Opened PR #432 on branch shiplock/" + path.id); }}>
                    Open a fix pull request
                  </button>
                ) : null}
                {status === "fixing" ? (
                  <button className="pr-btn pr-btn-primary pr-btn-sm"
                    onClick={() => { setStatus(path.id, "fixed"); toast("Merged. Re-audited: path closed."); onClose(); }}>
                    Simulate merge →
                  </button>
                ) : null}
                <button className="pr-btn pr-btn-ghost pr-btn-sm"
                  onClick={() => { setStatus(path.id, "fixed"); toast("Dismissed. It will come back if it reappears in a future audit."); onClose(); }}>
                  Dismiss
                </button>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </>
  );
}

function Gate({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="pr-row" style={{ fontSize: 14 }}>
      <span style={{ color: ok ? "var(--ok)" : "var(--muted-2)" }}>{ok ? "✓" : "○"}</span>
      <span>{label}</span>
    </div>
  );
}

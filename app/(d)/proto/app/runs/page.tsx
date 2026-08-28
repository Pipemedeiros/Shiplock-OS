"use client";

import { useState } from "react";
import { TRACE } from "../../data";
import { useProto } from "../../store";

const RUNS = [
  { id: "r-now", when: "11 minutes ago", trigger: "Deep audit · scheduled", found: 0, note: "5 open, unchanged", cost: "$1.86" },
  { id: "r-pr431", when: "12 minutes ago", trigger: "Pull request #431", found: 1, note: "Merge blocked", cost: "$0.34" },
  { id: "r-pr430", when: "2 hours ago", trigger: "Pull request #430", found: 0, note: "Clear", cost: "$0.29" },
  { id: "r-first", when: "6 days ago", trigger: "First audit · ledgerloop/app", found: 5, note: "Baseline established", cost: "$2.41" },
];

export default function RunsPage() {
  const [open, setOpen] = useState<string | null>("r-first");
  const { toast } = useProto();

  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Audit runs</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>Every run, written down.</h1>
          <p className="pr-sub" style={{ marginTop: 8, maxWidth: 600 }}>
            You are buying judgement, so you get to inspect it. Nothing here is a black box you
            have to take on faith.
          </p>
        </div>
        <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={() => toast("Deep audit queued — about 4 minutes")}>
          Run one now
        </button>
      </div>

      <div className="pr-card">
        <table className="pr-table">
          <thead>
            <tr><th>When</th><th>Trigger</th><th>Result</th><th style={{ textAlign: "right" }}>Trace</th></tr>
          </thead>
          <tbody>
            {RUNS.map((r) => (
              <tr key={r.id}>
                <td className="pr-sub">{r.when}</td>
                <td>{r.trigger}</td>
                <td>
                  {r.found > 0
                    ? <span className="pr-tag pr-tag-crit">{r.found} new</span>
                    : <span className="pr-tag pr-tag-ok">Clear</span>}
                  <span className="pr-sub" style={{ marginLeft: 10, fontSize: 13 }}>{r.note}</span>
                </td>
                <td style={{ textAlign: "right" }}>
                  <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={() => setOpen(open === r.id ? null : r.id)}>
                    {open === r.id ? "Hide" : "Read"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {open ? (
        <div className="pr-card" style={{ marginTop: 16 }}>
          <div className="pr-hd">
            <h3 className="pr-eyebrow">Trace · {RUNS.find((r) => r.id === open)?.trigger}</h3>
            <span className="pr-mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
              read-only checkout · torn down at the end
            </span>
          </div>
          <div className="pr-card-p pr-trace">
            {TRACE.map((s) => (
              <div key={s.t + s.body} className="pr-trace-line">
                <span className="pr-trace-t">{s.t}</span>
                <span className="pr-trace-i">{s.icon}</span>
                <span className="pr-trace-body">
                  <strong className={s.found ? "pr-trace-found" : undefined}>{s.body}</strong>
                  {s.note ? <div className="pr-trace-note">{s.note}</div> : null}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </>
  );
}

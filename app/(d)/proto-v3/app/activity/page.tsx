"use client";

import { useState } from "react";
import { PULL_REQUESTS, RESOLVED, RUNS, TRACE } from "../../data";
import { useStore } from "../../store";
import { Eyebrow } from "../../ui";

export default function ActivityPage() {
  const { toast } = useStore();
  const [openRun, setOpenRun] = useState<string | null>(null);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>Everything we did, and when</Eyebrow>
          <h1 className="v3-serif">Activity</h1>
        </div>
        <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Audit queued — visual only")}>Run an audit now</button>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Pull requests</h2>
            <span className="v3-small">Checked before merge</span>
          </div>
          <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {PULL_REQUESTS.map((p) => (
              <div key={p.number} className="v3-between" style={{ alignItems: "flex-start" }}>
                <div>
                  <div className="v3-row" style={{ gap: 8 }}>
                    <span className="v3-code-tag">#{p.number}</span>
                    <b style={{ fontWeight: 500, fontSize: 14.5 }}>{p.title}</b>
                    <span className="v3-small">{p.author}</span>
                  </div>
                  <p className="v3-small" style={{ marginTop: 3 }}>{p.verdict}</p>
                </div>
                <div className="v3-row" style={{ gap: 12 }}>
                  <span className="v3-small">{p.when}</span>
                  <span className={`v3-tag ${p.state === "blocked" ? "crit" : p.state === "warned" ? "warn" : p.state === "ours" ? "ok" : ""}`}>
                    {p.state === "clear" ? "clear" : p.state === "ours" ? "ours" : p.state}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Audit runs</h2>
            <span className="v3-small">Open one to read it line by line</span>
          </div>
          <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
            {RUNS.map((r) => (
              <div key={r.id} style={{ borderBottom: "1px solid var(--line-2)", padding: "13px 0" }}>
                <div className="v3-between" style={{ alignItems: "flex-start" }}>
                  <div>
                    <div className="v3-row" style={{ gap: 9 }}>
                      <b style={{ fontWeight: 500, fontSize: 14.5 }}>{r.kind}</b>
                      <span className="v3-file">{r.target}</span>
                    </div>
                    <p className="v3-small" style={{ marginTop: 3 }}>{r.outcome}</p>
                  </div>
                  <div className="v3-row" style={{ gap: 14 }}>
                    <span className="v3-small">{r.duration}</span>
                    <span className="v3-small">{r.when}</span>
                    <button className="v3-btn v3-btn-sm v3-quiet" onClick={() => setOpenRun(openRun === r.id ? null : r.id)}>
                      {openRun === r.id ? "Hide trace" : "Trace"}
                    </button>
                  </div>
                </div>
                {openRun === r.id ? (
                  <div className="v3-trace" style={{ marginTop: 12, paddingLeft: 2 }}>
                    {TRACE.map((s) => (
                      <div key={s.time + s.label} className={`v3-trace-line${s.found ? " found" : ""}`}>
                        <span className="v3-trace-t">{s.time}</span>
                        <span>
                          <b style={{ fontWeight: 400 }}>{s.label}</b>
                          {s.note ? <small>{s.note}</small> : null}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Closed</h2>
            <span className="v3-small">Last 30 days</span>
          </div>
          <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 13 }}>
            {RESOLVED.map((r) => (
              <div key={r.id} className="v3-between">
                <div className="v3-row" style={{ gap: 10 }}>
                  <span className="v3-tag ok">closed</span>
                  <span style={{ fontSize: 14 }}>{r.title}</span>
                </div>
                <div className="v3-row" style={{ gap: 14 }}>
                  <span className="v3-file">{r.closedBy}</span>
                  <span className="v3-small">{r.when}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}

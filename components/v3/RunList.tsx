"use client";

import { useState } from "react";
import type { DashboardRun } from "@/lib/agent/dashboardData";

/**
 * The run log, with the trace behind a disclosure.
 *
 * The trace is the trust device — a customer who can read what the audit did,
 * step by step, can disagree with it. It is collapsed by default because most
 * visits are not disputes, and expanded in place because opening a modal to
 * read a log is friction with no purpose.
 */
export function RunList({ runs }: { runs: DashboardRun[] }) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {runs.map((run) => (
        <div key={run.id} style={{ borderBottom: "1px solid var(--line-2)", padding: "13px 0" }}>
          <div className="v3-between" style={{ alignItems: "flex-start" }}>
            <div>
              <div className="v3-row" style={{ gap: 9 }}>
                <b style={{ fontWeight: 500, fontSize: 14.5 }}>
                  {run.trigger === "pull_request" ? "Pull request" : "Audit"}
                </b>
                <span className="v3-file">{run.fullName}</span>
                {run.status === "failed" ? <span className="v3-tag crit">stopped</span> : null}
              </div>
              <p className="v3-small" style={{ marginTop: 3 }}>
                {run.status === "failed"
                  ? run.error ?? "no reason recorded"
                  : `${run.filesRead ?? 0} files · ${run.entriesFound ?? 0} entries · ${run.tablesFound ?? 0} tables · ${run.findingsCount} ${run.findingsCount === 1 ? "finding" : "findings"}`}
              </p>
            </div>
            <div className="v3-row" style={{ gap: 14 }}>
              <span className="v3-small">{new Date(run.startedAt).toLocaleString()}</span>
              <button className="v3-btn v3-btn-sm v3-quiet" onClick={() => setOpen(open === run.id ? null : run.id)}>
                {open === run.id ? "Hide trace" : "Trace"}
              </button>
            </div>
          </div>

          {open === run.id ? (
            <div className="v3-trace" style={{ marginTop: 12 }}>
              {run.trace.length === 0 ? (
                <p className="v3-small">No trace was recorded for this run.</p>
              ) : (
                run.trace.map((s, i) => (
                  <div key={`${s.time}-${i}`} className={`v3-trace-line${s.found ? " found" : ""}`}>
                    <span className="v3-trace-t">{s.time}</span>
                    <span>
                      <b style={{ fontWeight: 400 }}>{s.label}</b>
                      {s.note ? <small>{s.note}</small> : null}
                    </span>
                  </div>
                ))
              )}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

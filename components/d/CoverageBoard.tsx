"use client";

// Real coverage board — Design D's shell, real data only. No PR-approval
// queue, no fake live engagement log, no per-check "receipt" transcripts:
// none of those have a real backend equivalent (see plan). Issues here are
// exactly what POST /api/scan returned for this user's latest scan,
// paywall-filtered server-side before this component ever sees them.

import { useRef, useState } from "react";
import { Lock } from "@/components/d/Lock";
import { DecryptText } from "@/components/d/bits";
import type { PreviewIssue, FullIssue, Severity } from "@/lib/types";

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  WARNING: "Warning",
  INFO: "Info",
};

const SEVERITY_CHIP: Record<Severity, string> = {
  CRITICAL: "dxd-chip-critical",
  WARNING: "dxd-chip-medium",
  INFO: "dxd-chip-low",
};

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  WARNING: 1,
  INFO: 2,
};

function isFullIssue(issue: PreviewIssue | FullIssue): issue is FullIssue {
  return "fix" in issue;
}

export function CoverageBoard({
  issues,
  totalChecks,
}: {
  issues: (PreviewIssue | FullIssue)[];
  totalChecks: number;
}) {
  const [openRow, setOpenRow] = useState<number | null>(null);
  const rowRefs = useRef<Record<number, HTMLElement | null>>({});

  const worst = [...issues].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  )[0];

  function jumpTo(index: number) {
    setOpenRow(index);
    setTimeout(() => {
      rowRefs.current[index]?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 60);
  }

  return (
    <>
      <h1 className="dxd-statement" aria-live="polite">
        {issues.length === 0 ? (
          <>
            <DecryptText text="Locked." /> You&apos;re <em className="dxd-em-ok">covered.</em>
          </>
        ) : (
          <>
            {["", "One thing", "Two things", "Three things", "Four things"][issues.length] ||
              `${issues.length} things`}{" "}
            <em>need{issues.length === 1 ? "s" : ""} you.</em> We hold the rest.
          </>
        )}
      </h1>

      <Lock totalChecks={totalChecks} issues={issues} onSelect={jumpTo} />

      <div className="dxd-substat">
        <span>
          worst open: <b>{worst ? SEVERITY_LABEL[worst.severity].toLowerCase() : "none"}</b>
        </span>
        <span>
          open findings <b>{issues.length}</b>
        </span>
      </div>

      <div className="dxd-dashgrid" style={{ gridTemplateColumns: "1fr" }}>
        <section className="dxd-board" aria-label={`Coverage board — ${totalChecks} checks`}>
          <div className="dxd-board-head">
            <span>Finding</span>
            <span>Severity &amp; consequence</span>
          </div>

          {issues.length === 0 && (
            <p style={{ padding: "24px 4px", color: "var(--d-muted)" }}>
              No open findings on your latest scan. Every check held.
            </p>
          )}

          {issues.map((issue, i) => {
            const opened = openRow === i;
            return (
              <article
                key={`${issue.title}-${i}`}
                ref={(el) => {
                  rowRefs.current[i] = el;
                }}
                className="dxd-row"
                data-needs
                data-open={opened}
              >
                <button
                  type="button"
                  className="dxd-row-btn"
                  aria-expanded={opened}
                  onClick={() => setOpenRow(opened ? null : i)}
                >
                  <span className={`dxd-chip ${SEVERITY_CHIP[issue.severity]}`}>
                    {SEVERITY_LABEL[issue.severity]}
                  </span>
                  <span className="dxd-row-name">
                    <h3>{issue.title}</h3>
                  </span>
                  <span className="dxd-row-chevron" aria-hidden="true">
                    ▾
                  </span>
                </button>

                {opened && (
                  <div className="dxd-row-body">
                    <p>
                      <strong>What it costs you if it stays — </strong>
                      {issue.consequence}
                    </p>

                    {isFullIssue(issue) ? (
                      <div className="dxd-brief">
                        <p className="dxd-brief-title">The brief · prepared for you</p>
                        <p style={{ fontSize: 14, lineHeight: 1.65 }}>{issue.fix}</p>
                        {issue.codefix && (
                          <>
                            <pre className="dxd-code">{issue.codefix.prompt}</pre>
                            <p className="dxd-keynote" style={{ margin: "8px 0 0" }}>
                              {issue.codefix.description} — {issue.codefix.file}
                            </p>
                          </>
                        )}
                      </div>
                    ) : (
                      <p className="dxd-locked-brief">Brief on retainer</p>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </section>
      </div>
    </>
  );
}

"use client";

// Real coverage board — Design D's shell, real data only. Issues here are
// exactly what POST /api/scan returned for this user's latest scan,
// paywall-filtered server-side before this component ever sees them.
//
// Split into two exports (2026-07-27) so the dashboard can put posture on the
// Overview page and the finding list on the Findings page:
//   PostureHeadline — the statement, the lock, the summary counts
//   FindingsBoard   — the expandable finding list
// CoverageBoard still composes both, which is what /dashboard-demo renders.
//
// Note on what these show: findings are named by RISK and CONSEQUENCE, never
// by the probe that found them. What we cover is public; how we detect it
// isn't.

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

export function PostureHeadline({
  issues,
  totalChecks,
  onSelect,
  layerLine,
  nextLayer,
}: {
  issues: (PreviewIssue | FullIssue)[];
  totalChecks: number;
  /** Optional — when absent, lock pins are inert (Overview has no board below). */
  onSelect?: (index: number) => void;
  /**
   * "4 of 5 layers correlated — code, database, …". Deliberately a count of
   * what is wired up, never a percentage: a percentage would imply we know what
   * fraction of the customer's risk we found, which nobody can know.
   */
  layerLine?: string;
  /** The next layer worth connecting, when one is missing. */
  nextLayer?: { label: string; href: string } | null;
}) {
  const worst = [...issues].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  )[0];

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

      <Lock totalChecks={totalChecks} issues={issues} onSelect={onSelect} />

      {layerLine && (
        <p className="dxd-layerline">
          {layerLine}
          {nextLayer && (
            <>
              {" "}
              <a href={nextLayer.href} className="dxd-layerline-cta">
                Connect {nextLayer.label} →
              </a>
            </>
          )}
        </p>
      )}

      <div className="dxd-substat">
        <span>
          worst open: <b>{worst ? SEVERITY_LABEL[worst.severity].toLowerCase() : "none"}</b>
        </span>
        <span>
          open findings <b>{issues.length}</b>
        </span>
      </div>
    </>
  );
}

/**
 * The agreement strip — which layers independently confirmed one finding.
 *
 * This is the product's whole differentiator made scannable: a single-layer
 * scanner can say "this policy looks permissive", and only a correlated one can
 * say "and the route that serves it has no auth check". Rendered only where
 * there is genuine agreement (2+ layers), so its presence is itself the signal
 * and its absence never implies a finding is weak — plenty of real findings come
 * from one layer.
 *
 * Deliberately not a graph: a force-directed diagram reads as enterprise
 * tooling, does not survive a phone screen, and would take longer to interpret
 * than the sentence underneath it.
 */
export function AgreementStrip({
  layers,
  proven,
}: {
  /** Layers that contributed evidence, in display order. */
  layers: { label: string; agreed: boolean }[];
  /** True when the finding was demonstrated on a replica, not inferred. */
  proven?: boolean;
}) {
  const agreedCount = layers.filter((l) => l.agreed).length;
  if (agreedCount < 2) return null;

  return (
    <p className="dxd-agreement" aria-label={`Confirmed by ${agreedCount} layers`}>
      {layers.map((l) => (
        <span key={l.label} className="dxd-agreement-layer" data-agreed={l.agreed}>
          <span aria-hidden="true">{l.agreed ? "●" : "○"}</span> {l.label}
        </span>
      ))}
      {proven && <span className="dxd-agreement-proven">proven, not inferred</span>}
    </p>
  );
}

export function FindingsBoard({
  issues,
  totalChecks,
}: {
  issues: (PreviewIssue | FullIssue)[];
  totalChecks: number;
}) {
  const [openRow, setOpenRow] = useState<number | null>(null);
  const rowRefs = useRef<Record<number, HTMLElement | null>>({});

  return (
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
                  {issue.correlation && (
                    <AgreementStrip
                      layers={issue.correlation.layers}
                      proven={issue.correlation.proven}
                    />
                  )}

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
  );
}

export function CoverageBoard({
  issues,
  totalChecks,
}: {
  issues: (PreviewIssue | FullIssue)[];
  totalChecks: number;
}) {
  const [jumpTarget, setJumpTarget] = useState<number | null>(null);

  return (
    <>
      <PostureHeadline issues={issues} totalChecks={totalChecks} onSelect={setJumpTarget} />
      <FindingsBoard issues={issues} totalChecks={totalChecks} key={jumpTarget ?? "board"} />
    </>
  );
}

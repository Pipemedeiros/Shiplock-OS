"use client";

import { useMemo, useState } from "react";
import { GitPullRequest, ShieldCheck, Wrench } from "lucide-react";
import { CONFIDENCE_RULE, type Confidence, type Risk, type Severity } from "../../data";
import { useStore } from "../../store";
import { Chain, Claims, Code, Conf, Eyebrow, Gates, Sev } from "../../ui";

type Tab = "why" | "code" | "fix";

export default function Risks() {
  const { openRisks, statusOf } = useStore();
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [confidence, setConfidence] = useState<Confidence | "all">("all");
  const [selectedId, setSelectedId] = useState<string>(openRisks[0]?.id ?? "");

  const visible = useMemo(
    () => openRisks.filter(
      (r) => (severity === "all" || r.severity === severity) && (confidence === "all" || r.confidence === confidence),
    ),
    [openRisks, severity, confidence],
  );

  const selected = visible.find((r) => r.id === selectedId) ?? visible[0];

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>Ordered by what they reach</Eyebrow>
          <h1 className="v3-serif">Every way in, and the check that is missing.</h1>
        </div>
      </div>

      <div className="v3-filters">
        <div className="v3-filter">
          <span>Severity</span>
          {(["all", "critical", "high", "medium"] as const).map((s) => (
            <button key={s} className={severity === s ? "on" : ""} onClick={() => setSeverity(s)}>{s}</button>
          ))}
        </div>
        <div className="v3-filter">
          <span>Confidence</span>
          {(["all", "proven", "corroborated", "inferred"] as const).map((c) => (
            <button key={c} className={confidence === c ? "on" : ""} onClick={() => setConfidence(c)}>{c}</button>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="v3-empty">
          <p>Nothing matches those filters.</p>
          <p className="v3-small" style={{ marginTop: 6 }}>Widen them to see the rest of the evidence.</p>
        </div>
      ) : (
        <div className="v3-risks">
          <div className="v3-risk-list">
            {visible.map((r) => (
              <button
                key={r.id}
                className={`v3-risk${selected?.id === r.id ? " on" : ""}`}
                onClick={() => setSelectedId(r.id)}
                aria-current={selected?.id === r.id}
              >
                <div className="v3-row">
                  <Sev severity={r.severity} />
                  <Conf confidence={r.confidence} />
                  <span className="v3-code-tag">{r.code}</span>
                  {statusOf(r.id) === "fixing" ? <span className="v3-tag ok">fix open</span> : null}
                </div>
                <h2>{r.title}</h2>
                <p>{r.consequence}</p>
                <Chain risk={r} compact />
                <p className="v3-small">{r.area} · open {r.age}</p>
              </button>
            ))}
          </div>

          {selected ? <Inspector risk={selected} /> : null}
        </div>
      )}
    </>
  );
}

function Inspector({ risk }: { risk: Risk }) {
  const [tab, setTab] = useState<Tab>("why");
  const { setStatus, statusOf, toast } = useStore();
  const status = statusOf(risk.id);
  const gatesPassed = risk.gates.every((g) => g.passed);

  return (
    <aside className="v3-inspector">
      <div className="v3-card-p">
        <div className="v3-row">
          <Sev severity={risk.severity} />
          <Conf confidence={risk.confidence} />
          <span className="v3-code-tag">{risk.code}</span>
        </div>
        <h2 className="v3-serif" style={{ fontSize: 21, margin: "12px 0 8px" }}>{risk.title}</h2>
        <p className="v3-sub" style={{ fontSize: 14 }}>{risk.consequence}</p>
        <Chain risk={risk} />
        <p className="v3-small" style={{ marginTop: 14 }}>
          <span className="v3-eyebrow">Blast radius</span> {risk.blastRadius}
        </p>
      </div>

      <div className="v3-tabs">
        {([["why", "Why we believe this"], ["code", "The code"], ["fix", "The fix"]] as const).map(([k, label]) => (
          <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{label}</button>
        ))}
      </div>

      <div className="v3-card-p">
        {tab === "why" ? (
          <>
            <Claims claims={risk.claims} />
            <div
              className="v3-card v3-card-p"
              style={{ marginTop: 18, borderColor: risk.proof ? "rgba(30,122,85,.4)" : "var(--line)" }}
            >
              <div className="v3-row">
                {risk.proof ? <ShieldCheck size={15} style={{ color: "var(--ok)" }} /> : null}
                <span className="v3-eyebrow" style={{ color: risk.proof ? "var(--ok)" : undefined }}>
                  {risk.proof ? "Reproduced" : "Not reproduced"}
                </span>
              </div>
              <p style={{ marginTop: 8, fontSize: 14 }}>{risk.proof ?? risk.notProvenBecause}</p>
              <p className="v3-small" style={{ marginTop: 10 }}>{CONFIDENCE_RULE[risk.confidence]}</p>
            </div>
          </>
        ) : null}

        {tab === "code" ? (
          <>
            <p className="v3-file" style={{ marginBottom: 10 }}>{risk.file}</p>
            <Code>{risk.vulnerableCode}</Code>
            <button className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 14 }} onClick={() => toast(`Opening ${risk.file} on GitHub`)}>
              View on GitHub
            </button>
          </>
        ) : null}

        {tab === "fix" ? (
          <div className="v3-stack" style={{ gap: 16 }}>
            <div>
              <div className="v3-row" style={{ marginBottom: 8 }}>
                {risk.fixKind === "pr" ? <GitPullRequest size={15} /> : risk.fixKind === "one_click" ? <ShieldCheck size={15} /> : <Wrench size={15} />}
                <b style={{ fontWeight: 500 }}>{risk.fixTitle}</b>
              </div>
              <p className="v3-small">{FIX_NOTE[risk.fixKind]}</p>
            </div>

            <Code>{risk.fixDiff}</Code>

            {risk.fixKind === "manual" ? null : (
              <div className="v3-card v3-card-p">
                <div className="v3-between" style={{ marginBottom: 4 }}>
                  <span className="v3-eyebrow">Before we offer it</span>
                  <span className={`v3-tag ${gatesPassed ? "ok" : "warn"}`}>
                    {risk.gates.filter((g) => g.passed).length} of {risk.gates.length} checks passed
                  </span>
                </div>
                <Gates gates={risk.gates} />
              </div>
            )}

            <div className="v3-row">
              {risk.fixKind === "pr" && status === "open" ? (
                <button
                  className="v3-btn v3-btn-sm v3-primary"
                  disabled={!gatesPassed}
                  onClick={() => { setStatus(risk.id, "fixing"); toast(`Opened PR #432 on branch shiplock/${risk.id}`); }}
                >
                  Open a fix pull request
                </button>
              ) : null}
              {risk.fixKind === "one_click" && status === "open" ? (
                <button
                  className="v3-btn v3-btn-sm v3-primary"
                  disabled={!gatesPassed}
                  onClick={() => { setStatus(risk.id, "fixed"); toast("Applied. The previous policy is stored — undo any time."); }}
                >
                  Apply it
                </button>
              ) : null}
              {status === "fixing" ? (
                <button
                  className="v3-btn v3-btn-sm v3-primary"
                  onClick={() => { setStatus(risk.id, "fixed"); toast("Merged. Re-audited: the path is closed."); }}
                >
                  Simulate merge
                </button>
              ) : null}
              <button className="v3-btn v3-btn-sm v3-quiet" onClick={() => { setStatus(risk.id, "fixed"); toast("Dismissed. It returns if a later audit finds it again."); }}>
                Dismiss
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

/** The three fix tiers, said plainly. Never one button for all of them. */
const FIX_NOTE: Record<Risk["fixKind"], string> = {
  pr: "Opened on its own branch, for you to read and merge. We never push to your default branch.",
  one_click: "Small, additive and reversible. We store the previous state before changing anything, so undo is one click.",
  manual: "This is a decision about your architecture, not a mechanical change. We wrote the suggestion; the call is yours.",
};

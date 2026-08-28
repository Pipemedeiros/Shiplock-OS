"use client";

import {
  ArrowRight,
  Check,
  ChevronDown,
  CircleDot,
  Code2,
  FileCode2,
  GitPullRequestArrow,
  ListFilter,
  ShieldCheck,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import { RISKS, type Confidence, type Risk, type Severity } from "../../data";
import { useConcept } from "../../store";
import { ConfidenceBadge, PageHeader, RiskPath, SeverityBadge } from "../../ui";

type DetailTab = "reasoning" | "evidence" | "fix";

export default function PathsPage() {
  const { dismissed } = useConcept();
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [confidence, setConfidence] = useState<Confidence | "all">("all");
  const [selected, setSelected] = useState<Risk>(RISKS[0]);

  const visible = useMemo(
    () => RISKS.filter((risk) => !dismissed.includes(risk.id) && (severity === "all" || risk.severity === severity) && (confidence === "all" || risk.confidence === confidence)),
    [dismissed, severity, confidence],
  );

  return (
    <>
      <PageHeader
        eyebrow="Attack paths · ordered by consequence"
        title={<>Every way in, with the <em>boundary that failed.</em></>}
        description="A path is shown only when an application entry can be followed through identity and authorization to a meaningful asset. Confidence stays attached to the claim."
        actions={<button className="cx-button is-ghost"><ListFilter size={14} />{visible.length} paths in view</button>}
      />

      <div className="cx-filterbar cx-reveal">
        <div className="cx-filter-group"><span>Severity</span>{(["all", "critical", "high", "medium"] as const).map((item) => <button key={item} className={severity === item ? "is-active" : ""} onClick={() => setSeverity(item)}>{item}</button>)}</div>
        <div className="cx-filter-group"><span>Confidence</span>{(["all", "proven", "corroborated", "inferred"] as const).map((item) => <button key={item} className={confidence === item ? "is-active" : ""} onClick={() => setConfidence(item)}>{item}</button>)}</div>
      </div>

      <section className="cx-paths-layout">
        <div className="cx-path-list">
          {visible.map((risk, index) => (
            <button key={risk.id} className={`cx-path-card cx-reveal${selected.id === risk.id ? " is-selected" : ""}`} onClick={() => setSelected(risk)} style={{ "--delay": `${index * 55}ms` } as React.CSSProperties}>
              <span className="cx-path-card-index">{String(index + 1).padStart(2, "0")}</span>
              <div className="cx-path-card-main">
                <div className="cx-badge-row"><SeverityBadge severity={risk.severity} /><ConfidenceBadge confidence={risk.confidence} /><span className="cx-code-tag">{risk.code}</span></div>
                <h2>{risk.title}</h2>
                <p>{risk.consequence}</p>
                <RiskPath risk={risk} compact />
                <div className="cx-path-meta"><span>{risk.owner}</span><i /><span>Open {risk.age}</span><i /><span>{risk.blastRadius.split(" · ")[0]}</span></div>
              </div>
              <span className="cx-path-open"><ArrowRight size={16} /></span>
            </button>
          ))}
          {!visible.length ? <div className="cx-empty-state"><ShieldCheck size={28} /><h2>No paths match these filters.</h2><p>Change the confidence or severity filter to restore the full evidence set.</p></div> : null}
        </div>
        <RiskInspector risk={selected} />
      </section>
    </>
  );
}

function RiskInspector({ risk }: { risk: Risk }) {
  const [tab, setTab] = useState<DetailTab>("reasoning");
  const { dismiss, toast } = useConcept();

  return (
    <aside className="cx-inspector cx-reveal">
      <div className="cx-inspector-head">
        <div className="cx-badge-row"><SeverityBadge severity={risk.severity} /><ConfidenceBadge confidence={risk.confidence} /></div>
        <span>{risk.code}</span>
        <h2>{risk.title}</h2>
        <p>{risk.consequence}</p>
        <RiskPath risk={risk} />
        <div className="cx-blast"><span>Observed blast radius</span><strong>{risk.blastRadius}</strong></div>
      </div>
      <div className="cx-inspector-tabs">
        {(["reasoning", "evidence", "fix"] as const).map((item) => <button key={item} className={tab === item ? "is-active" : ""} onClick={() => setTab(item)}>{item === "reasoning" ? "Why we think so" : item}</button>)}
      </div>
      <div className="cx-inspector-body">
        {tab === "reasoning" ? (
          <div className="cx-reasoning-list">
            {risk.evidence.map((item, index) => <div key={item}><span>{index + 1}</span><p>{item}</p></div>)}
            <div className={`cx-confidence-note is-${risk.confidence}`}><ConfidenceBadge confidence={risk.confidence} /><p>{risk.confidence === "proven" ? "Reproduced with synthetic tenants on a disposable copy. No production rows were read." : risk.confidence === "corroborated" ? "Two independent code observations agree. No replay was required for this claim." : "Code indicates the path, but an external boundary we cannot observe may compensate."}</p></div>
          </div>
        ) : null}
        {tab === "evidence" ? (
          <div className="cx-evidence-view">
            <div className="cx-evidence-file"><FileCode2 size={15} /><span>{risk.file}</span><button onClick={() => toast("GitHub location opened — visual demo")}>Open <ArrowRight size={12} /></button></div>
            <pre>{risk.diff.split("\n").slice(0, 7).map((line, index) => <code key={`${line}-${index}`} className={line.startsWith("+") ? "is-add" : line.startsWith("-") ? "is-remove" : ""}><span>{String(index + 12).padStart(2, "0")}</span>{line}</code>)}</pre>
            <div className="cx-evidence-facts"><div><Code2 size={15} /><span><strong>6 sibling routes</strong><small>All enforce workspace ownership</small></span></div><div><CircleDot size={15} /><span><strong>1 conflicting route</strong><small>This is the outlier</small></span></div></div>
          </div>
        ) : null}
        {tab === "fix" ? (
          <div className="cx-fix-view">
            <div className="cx-fix-summary"><span><GitPullRequestArrow size={17} /></span><div><strong>{risk.fix}</strong><small>Proposed on a new branch. Never merged by ShipLock.</small></div></div>
            <div className="cx-gate-list">
              {risk.gates.map((gate) => <div key={gate.label} className={gate.passed ? "is-passed" : ""}><span>{gate.passed ? <Check size={13} /> : <X size={13} />}</span><div><strong>{gate.label}</strong><small>{gate.detail}</small></div></div>)}
            </div>
            <pre className="cx-diff">{risk.diff}</pre>
            <button className="cx-button is-bronze" onClick={() => toast(`Fix PR prepared for ${risk.code} — display only`)} disabled={risk.gates.some((gate) => !gate.passed)}><GitPullRequestArrow size={14} />Open validated fix PR</button>
          </div>
        ) : null}
      </div>
      <div className="cx-inspector-foot">
        <button className="cx-text-button" onClick={() => dismiss(risk.id)}>Dismiss path</button>
        <button className="cx-text-button">Assign to {risk.owner} <ChevronDown size={12} /></button>
      </div>
    </aside>
  );
}

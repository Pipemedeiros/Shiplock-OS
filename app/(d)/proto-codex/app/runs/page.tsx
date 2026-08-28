"use client";

import {
  Activity,
  ArrowRight,
  CalendarDays,
  Check,
  Clock3,
  GitCommitHorizontal,
  Play,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { RUNS, TRACE } from "../../data";
import { useConcept } from "../../store";
import { PageHeader, RunGlyph, StatusPill } from "../../ui";

export default function RunsPage() {
  const [selected, setSelected] = useState(RUNS[0]);
  const [playing, setPlaying] = useState(false);
  const { toast } = useConcept();

  return (
    <>
      <PageHeader
        eyebrow="Audit runs · full execution trace"
        title={<>Every judgement has <em>a receipt.</em></>}
        description="Read the exact sequence from checkout to map, proof, fix validation, and teardown. A clean run and a run that never reached an asset are visibly different states."
        actions={<button className="cx-button is-dark" onClick={() => { setPlaying(true); toast("Fresh audit queued — display only"); }}><Play size={14} />Run deep audit</button>}
      />

      <section className="cx-run-metrics cx-reveal">
        <div><span><Activity size={15} />Runs this month</span><strong>147</strong><small>142 completed clear</small></div>
        <div><span><Clock3 size={15} />Average duration</span><strong>1m 04s</strong><small>Deep audit 4m 26s</small></div>
        <div><span><ShieldCheck size={15} />Proof environments</span><strong>12</strong><small>All destroyed after use</small></div>
        <div><span><CalendarDays size={15} />Next scheduled</span><strong>6h 18m</strong><small>Full repository audit</small></div>
      </section>

      <section className="cx-runs-layout">
        <div className="cx-run-list cx-panel cx-reveal">
          <div className="cx-panel-head"><div><h2>Recent runs</h2></div><button className="cx-icon-button" aria-label="Refresh runs"><RotateCcw size={14} /></button></div>
          {playing ? <button className="cx-run-row is-live"><span className="cx-run-state"><i className="cx-status-dot is-bronze" /></span><span><strong>Deep audit</strong><small>Manual · current main</small></span><span className="cx-live-copy">Mapping entries…</span><span className="cx-progress-ring">32%</span></button> : null}
          {RUNS.map((run) => (
            <button key={run.id} className={`cx-run-row${selected.id === run.id ? " is-selected" : ""}`} onClick={() => setSelected(run)}>
              <span className={`cx-run-state is-${run.state}`}>{run.state === "complete" ? <Check size={14} /> : "!"}</span>
              <span><strong>{run.label}</strong><small>{run.trigger} · {run.commit}</small></span>
              <span><StatusPill tone={run.state === "blocked" ? "signal" : run.state === "warning" ? "attention" : "verified"}>{run.paths ? `${run.paths} new` : "clear"}</StatusPill></span>
              <span className="cx-run-time"><strong>{run.time}</strong><small>{run.duration}</small></span>
            </button>
          ))}
        </div>

        <article className="cx-run-trace cx-panel cx-reveal">
          <div className="cx-trace-header">
            <div><span className="cx-trace-icon"><GitCommitHorizontal size={17} /></span><span><small>{selected.id} · {selected.commit}</small><h2>{selected.label}</h2></span></div>
            <div><span>Coverage</span><strong>{selected.coverage}%</strong></div>
          </div>
          <div className="cx-trace-summary">
            <span><i className="is-verified" />{selected.trigger}</span><span><i className="is-bronze" />{selected.duration}</span><span><i className="is-signal" />{selected.paths} new paths</span><span>read-only checkout</span>
          </div>
          <div className="cx-full-trace">
            {TRACE.map((step, index) => (
              <div key={`${step.time}-${step.label}`} className={step.alert ? "is-alert" : ""}>
                <time>{step.time}</time>
                <span className="cx-trace-rail"><i><RunGlyph phase={step.phase} alert={step.alert} /></i>{index < TRACE.length - 1 ? <em /> : null}</span>
                <span><strong>{step.label}</strong><small>{step.note}</small></span>
                {step.phase === "proof" ? <button onClick={() => toast("Proof receipt opened — visual demo")}>receipt <ArrowRight size={11} /></button> : null}
              </div>
            ))}
          </div>
          <div className="cx-trace-footer"><ShieldCheck size={16} /><span><strong>Run closed cleanly.</strong> The disposable environment was destroyed and no customer data was retained.</span></div>
        </article>
      </section>
    </>
  );
}

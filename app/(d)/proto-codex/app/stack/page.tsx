"use client";

import {
  ArrowRight,
  Braces,
  Check,
  Database,
  Eye,
  Info,
  Layers3,
  Network,
  Plus,
} from "lucide-react";
import { useState } from "react";
import { STACK } from "../../data";
import { useConcept } from "../../store";
import { PageHeader, StatusPill } from "../../ui";

export default function StackPage() {
  const [active, setActive] = useState(STACK[0]);
  const { databaseConnected, update, toast } = useConcept();

  return (
    <>
      <PageHeader
        eyebrow="Your stack · inferred from source"
        title={<>The map your repository <em>already declares.</em></>}
        description="Manifests, imports, route boundaries, schemas, and environment variable names reveal how the application is assembled. Each claim says how deeply ShipLock understands it."
        actions={<button className="cx-button is-ghost" onClick={() => toast("Stack map refreshed — display only")}><Braces size={14} />Refresh from main</button>}
      />

      <section className="cx-stack-layout">
        <article className="cx-stack-map cx-panel cx-reveal">
          <div className="cx-panel-head"><div><Network size={16} /><h2>Application topology</h2></div><StatusPill tone="verified">6 systems mapped</StatusPill></div>
          <div className="cx-topology">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <path d="M50 12 L20 33 L28 75 L50 48 L72 76 L80 32 Z" />
              <path d="M20 33 L50 48 L80 32 M28 75 L72 76" />
            </svg>
            <div className="cx-topology-core"><Layers3 size={22} /><strong>ledgerloop/app</strong><small>138k lines</small></div>
            {STACK.map((item) => (
              <button
                key={item.id}
                className={`cx-system-node${active.id === item.id ? " is-active" : ""}`}
                style={{ left: `${item.x}%`, top: `${item.y}%` }}
                onClick={() => setActive(item)}
              >
                <span>{item.name.slice(0, 2).toUpperCase()}</span><strong>{item.name}</strong><small>{item.role}</small>
              </button>
            ))}
            <span className="cx-map-scanline" />
          </div>
          <div className="cx-topology-legend"><span><i className="is-read" />Observed in source</span><span><i className="is-map" />Usage mapped</span><span><i className="is-infer" />External state inferred</span></div>
        </article>

        <aside className="cx-stack-detail cx-panel cx-reveal">
          <div className="cx-stack-detail-head"><span className="cx-stack-monogram">{active.name.slice(0, 2).toUpperCase()}</span><div><small>{active.role}</small><h2>{active.name}</h2></div></div>
          <div className="cx-stack-depth"><span>Understanding depth</span><strong>{active.confidence}</strong><div><i style={{ width: active.confidence === "Mapped" ? "92%" : active.confidence === "Observed" ? "70%" : active.confidence === "Reasoned" ? "78%" : "48%" }} /></div></div>
          <p className="cx-stack-detail-copy">{active.detail}. ShipLock follows how this system is reached from application entries and records what is known versus assumed.</p>
          <div className="cx-stack-facts">
            <p className="cx-panel-label">Source evidence</p>
            <div><Check size={13} /><span>Declared in package.json and lockfile</span></div>
            <div><Check size={13} /><span>Import graph resolved across helpers</span></div>
            <div><Check size={13} /><span>Environment variable names inventoried</span></div>
            <div className={active.confidence === "Inferred" ? "is-unknown" : ""}>{active.confidence === "Inferred" ? <Info size={13} /> : <Check size={13} />}<span>Provider-side policy {active.confidence === "Inferred" ? "not observed" : "corroborated"}</span></div>
          </div>
          <button className="cx-button is-dark" onClick={() => toast(`${active.name} evidence opened — visual demo`)}>Inspect evidence <ArrowRight size={13} /></button>
        </aside>
      </section>

      <section className="cx-stack-inventory cx-reveal">
        {STACK.map((item) => (
          <button key={item.id} onClick={() => setActive(item)} className={active.id === item.id ? "is-active" : ""}>
            <span>{item.name.slice(0, 2).toUpperCase()}</span><div><strong>{item.name}</strong><small>{item.role}</small></div><em>{item.confidence}</em>
          </button>
        ))}
      </section>

      <section className="cx-optional-proof cx-reveal">
        <div className="cx-optional-icon">{databaseConnected ? <Check size={19} /> : <Database size={19} />}</div>
        <div><span>{databaseConnected ? "Optional database evidence connected" : "Where source alone stops"}</span><strong>{databaseConnected ? "Runtime policy can now corroborate the code map." : "Add read-only database evidence to upgrade selected inferred paths."}</strong><p>This is optional. GitHub remains enough to map the product and find code-level paths; an external boundary is never silently assumed safe.</p></div>
        <button className={`cx-button ${databaseConnected ? "is-ghost-light" : "is-bronze"}`} onClick={() => { update({ databaseConnected: !databaseConnected }); toast(databaseConnected ? "Optional evidence disconnected" : "Optional evidence connected — visual demo"); }}>{databaseConnected ? <><Eye size={14} />Connected</> : <><Plus size={14} />Add evidence</>}</button>
      </section>
    </>
  );
}

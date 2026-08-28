"use client";

import Link from "next/link";
import {
  ArrowRight,
  Braces,
  Check,
  GitBranch,
  Layers3,
  MousePointer2,
  Play,
  Route,
  ShieldCheck,
} from "lucide-react";
import { RISKS, TRACE } from "./data";
import { Brand, ConfidenceBadge, ExposureRadar, RiskPath, SeverityBadge } from "./ui";

export default function ConceptLanding() {
  const featured = RISKS[0];

  return (
    <div className="cx-landing">
      <div className="cx-landing-grid" />
      <nav className="cx-landing-nav">
        <Link href="/proto-codex"><Brand /></Link>
        <div className="cx-landing-links">
          <a href="#system">System</a>
          <a href="#motion">Motion</a>
          <Link href="/proto-codex/app">Dashboard</Link>
          <Link href="/proto-codex/onboarding" className="cx-button is-bronze">Enter concept <ArrowRight size={15} /></Link>
        </div>
      </nav>

      <section className="cx-hero">
        <div className="cx-hero-copy cx-reveal">
          <p className="cx-kicker"><span>Dashboard exploration 02</span><i />Display-only concept</p>
          <h1>Your application,<br /><em>seen end to end.</em></h1>
          <p className="cx-hero-lede">
            A detailed security workspace that turns repository evidence into a living map of entries,
            identity boundaries, customer data, and the fixes waiting for a decision.
          </p>
          <div className="cx-hero-actions">
            <Link href="/proto-codex/app" className="cx-button is-bronze">Explore the dashboard <ArrowRight size={15} /></Link>
            <Link href="/proto-codex/onboarding" className="cx-button is-ghost-light"><Play size={14} />Watch first audit</Link>
          </div>
          <div className="cx-hero-footnotes">
            <span><Check size={13} />Sample data only</span>
            <span><Check size={13} />No backend calls</span>
            <span><Check size={13} />Every screen included</span>
          </div>
        </div>

        <div className="cx-hero-visual cx-reveal">
          <div className="cx-hero-radar"><ExposureRadar /></div>
          <div className="cx-hero-float is-top">
            <span className="cx-status-dot is-signal" />
            <div><small>Path reproduced</small><strong>Cross-workspace read</strong></div>
          </div>
          <div className="cx-hero-float is-bottom">
            <ShieldCheck size={18} />
            <div><small>Fix validation</small><strong>3 / 3 gates passed</strong></div>
          </div>
        </div>
      </section>

      <div className="cx-landing-marquee" aria-hidden="true">
        <div>
          <span>63 entry points mapped</span><i />
          <span>24 data assets traced</span><i />
          <span>4 open attack paths</span><i />
          <span>3 validated fixes ready</span><i />
          <span>63 entry points mapped</span><i />
          <span>24 data assets traced</span><i />
          <span>4 open attack paths</span><i />
          <span>3 validated fixes ready</span><i />
        </div>
      </div>

      <section className="cx-landing-section" id="system">
        <div className="cx-section-intro">
          <p>One system, not a pile of cards</p>
          <h2>The dashboard keeps the reasoning visible.</h2>
          <span>Every screen answers a different part of the same question: what can reach customer data, why do we believe it, and what happens next?</span>
        </div>
        <div className="cx-principle-grid">
          {[
            { n: "01", icon: Route, title: "Paths before findings", copy: "The visual unit is entry → identity → missing boundary → data. The consequence and blast radius lead; the source location follows." },
            { n: "02", icon: Layers3, title: "Confidence is structural", copy: "Proven, corroborated, and inferred are treated as product states—not disclaimer text buried at the bottom of a drawer." },
            { n: "03", icon: GitBranch, title: "Every decision has a trace", copy: "Audits read like a flight recorder. Fixes show reproduction, attack-stop, and legitimate-flow gates before any action is offered." },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <article className="cx-principle" key={item.n}>
                <div><span>{item.n}</span><Icon size={19} /></div>
                <h3>{item.title}</h3>
                <p>{item.copy}</p>
              </article>
            );
          })}
        </div>
      </section>

      <section className="cx-finding-stage">
        <div className="cx-finding-window">
          <div className="cx-window-bar">
            <span><i /><i /><i /></span>
            <strong>ledgerloop/app · attack paths · {featured.code}</strong>
            <span>4f1e9c2</span>
          </div>
          <div className="cx-finding-content">
            <div className="cx-finding-copy">
              <div className="cx-badge-row"><SeverityBadge severity={featured.severity} /><ConfidenceBadge confidence={featured.confidence} /></div>
              <h2>{featured.title}</h2>
              <p>{featured.consequence}</p>
              <RiskPath risk={featured} />
              <div className="cx-blast"><span>Observed blast radius</span><strong>{featured.blastRadius}</strong></div>
            </div>
            <div className="cx-finding-proof">
              <p className="cx-panel-label">Why this is proven</p>
              {featured.gates.map((gate, index) => (
                <div className="cx-gate" key={gate.label} style={{ "--delay": `${index * 130}ms` } as React.CSSProperties}>
                  <span><Check size={13} /></span><div><strong>{gate.label}</strong><small>{gate.detail}</small></div>
                </div>
              ))}
              <button className="cx-button is-dark">Inspect evidence <ArrowRight size={14} /></button>
            </div>
          </div>
        </div>
      </section>

      <section className="cx-landing-section cx-motion-section" id="motion">
        <div className="cx-section-intro">
          <p>Motion with a job</p>
          <h2>The interface feels alive because the work is alive.</h2>
          <span>Motion establishes order, state, and causality. Every loop yields to reduced-motion preferences.</span>
        </div>
        <div className="cx-motion-grid">
          <div className="cx-motion-card is-trace">
            <div className="cx-motion-title"><Braces size={18} /><span>Audit trace</span><small>live</small></div>
            <div className="cx-mini-trace">
              {TRACE.slice(0, 5).map((step, index) => (
                <div key={step.time} style={{ "--delay": `${index * 180}ms` } as React.CSSProperties}>
                  <span>{step.time}</span><i className={step.alert ? "is-alert" : ""} /><p>{step.label}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="cx-motion-card is-pointer">
            <div className="cx-motion-title"><MousePointer2 size={18} /><span>Evidence follows attention</span></div>
            <div className="cx-hover-demo">
              <span className="cx-demo-pointer"><MousePointer2 size={18} /></span>
              <div><small>app/api/invoices/[id]/route.ts:14</small><strong>Workspace scope missing</strong><p>The route knows who the user is, but not which workspace they belong to.</p></div>
            </div>
          </div>
        </div>
      </section>

      <section className="cx-landing-cta">
        <div><p>Ten screens. One coherent system.</p><h2>Open the full dashboard concept.</h2></div>
        <Link href="/proto-codex/app" className="cx-button is-bronze">Explore every page <ArrowRight size={15} /></Link>
      </section>

      <footer className="cx-landing-footer">
        <Brand compact />
        <span>Display-only exploration · no production services · no real customer data</span>
      </footer>
    </div>
  );
}

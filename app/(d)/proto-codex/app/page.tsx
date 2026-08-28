"use client";

import Link from "next/link";
import {
  ArrowRight,
  Check,
  ChevronRight,
  Clock3,
  GitPullRequestArrow,
  Radar,
  ShieldCheck,
} from "lucide-react";
import { ACTIVITY, PULL_REQUESTS, RISKS } from "../data";
import { useConcept } from "../store";
import {
  ConfidenceBadge,
  ExposureRadar,
  Metric,
  MiniSparkline,
  PageHeader,
  RiskPath,
  SeverityBadge,
  StatusPill,
} from "../ui";

export default function OverviewPage() {
  const { dismissed, toast } = useConcept();
  const openRisks = RISKS.filter((risk) => !dismissed.includes(risk.id));
  const criticals = openRisks.filter((risk) => risk.severity === "critical");
  const lead = openRisks[0] ?? RISKS[0];

  return (
    <>
      <PageHeader
        eyebrow="Security overview · live posture"
        title={<>{criticals.length} ways in reach <em>customer data.</em></>}
        description="The latest deep audit inspected 96% of mapped application entries. Nothing new appeared; four existing paths remain open."
        actions={<><span className="cx-audit-time"><span className="cx-status-dot is-verified" />Audited 11m ago</span><Link href="/proto-codex/app/paths" className="cx-button is-dark">Review paths <ArrowRight size={14} /></Link></>}
      />

      <section className="cx-metric-grid">
        <Metric label="Open paths" value={String(openRisks.length)} detail="2 proven · 1 corroborated · 1 inferred" tone="signal" />
        <Metric label="Mapped entries" value="63" detail="96% inspected in the latest deep audit" trend="up" />
        <Metric label="Fixes ready" value="3" detail="All validation gates passed" tone="verified" />
        <Metric label="Mean time open" value="3.4d" detail="Down 28% over the last 30 days" trend="down" tone="bronze" />
      </section>

      <section className="cx-overview-grid">
        <article className="cx-panel cx-lead-risk cx-reveal">
          <div className="cx-panel-head">
            <div><span className="cx-panel-index">01</span><h2>Deal with this first</h2></div>
            <span className="cx-file-ref">{lead.file}</span>
          </div>
          <div className="cx-lead-body">
            <div className="cx-badge-row"><SeverityBadge severity={lead.severity} /><ConfidenceBadge confidence={lead.confidence} /><span className="cx-code-tag">{lead.code}</span></div>
            <h3>{lead.title}</h3>
            <p>{lead.consequence}</p>
            <RiskPath risk={lead} compact />
            <div className="cx-blast is-inline"><span>Blast radius</span><strong>{lead.blastRadius}</strong></div>
            <div className="cx-lead-actions">
              <Link href={`/proto-codex/app/paths?risk=${lead.id}`} className="cx-button is-bronze">Inspect evidence <ArrowRight size={14} /></Link>
              <span><ShieldCheck size={15} />Fix validated on a disposable environment</span>
            </div>
          </div>
        </article>

        <article className="cx-panel cx-map-panel cx-reveal">
          <div className="cx-panel-head">
            <div><Radar size={16} /><h2>Exposure map</h2></div>
            <StatusPill tone="verified">observing</StatusPill>
          </div>
          <ExposureRadar compact />
          <div className="cx-map-legend">
            <span><i className="is-signal" />Break in boundary</span>
            <span><i className="is-bronze" />Observed entry</span>
            <span><i className="is-verified" />Protected path</span>
          </div>
        </article>
      </section>

      <section className="cx-overview-lower">
        <article className="cx-panel cx-activity-panel cx-reveal">
          <div className="cx-panel-head">
            <div><Clock3 size={16} /><h2>Since your last look</h2></div>
            <Link href="/proto-codex/app/runs" className="cx-panel-link">Full trace <ChevronRight size={13} /></Link>
          </div>
          <div className="cx-activity-list">
            {ACTIVITY.map((item) => (
              <div key={item.title}>
                <span className={`cx-activity-icon is-${item.tone}`}><i /></span>
                <span><strong>{item.title}</strong><small>{item.detail}</small></span>
                <time>{item.time}</time>
              </div>
            ))}
          </div>
        </article>

        <article className="cx-panel cx-pr-panel cx-reveal">
          <div className="cx-panel-head">
            <div><GitPullRequestArrow size={16} /><h2>Waiting on you</h2></div>
            <span className="cx-panel-count">3</span>
          </div>
          <div className="cx-mini-prs">
            {PULL_REQUESTS.filter((pull) => pull.state !== "clear").slice(0, 3).map((pull) => (
              <Link key={pull.number} href="/proto-codex/app/prs">
                <span className={`cx-pr-state is-${pull.state}`}>{pull.state === "ours" ? <Check size={13} /> : "!"}</span>
                <span><strong>#{pull.number} {pull.title}</strong><small>{pull.verdict}</small></span>
                <ChevronRight size={14} />
              </Link>
            ))}
          </div>
        </article>

        <article className="cx-panel cx-cadence-panel cx-reveal">
          <div className="cx-panel-head"><div><h2>Audit cadence</h2></div><span>30 days</span></div>
          <div className="cx-cadence-chart">
            <div><strong>147</strong><span>runs completed</span></div>
            <MiniSparkline tone="verified" />
          </div>
          <div className="cx-cadence-foot"><span><i className="is-verified" />142 clear</span><span><i className="is-signal" />5 surfaced paths</span></div>
        </article>
      </section>

      <section className="cx-report-strip cx-reveal">
        <div className="cx-report-seal"><ShieldCheck size={23} /></div>
        <div><span>Shareable posture report</span><strong>Your enterprise prospect can verify coverage without seeing open findings.</strong></div>
        <button className="cx-button is-ghost-light" onClick={() => toast("Report link copied — visual demo")}>Copy report link <ArrowRight size={14} /></button>
      </section>
    </>
  );
}

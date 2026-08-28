"use client";

import {
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  Download,
  ExternalLink,
  FileCheck2,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useState } from "react";
import { QUESTIONNAIRE } from "../../data";
import { useConcept } from "../../store";
import { Brand, PageHeader } from "../../ui";

export default function ReportPage() {
  const { reportPublic, update, toast } = useConcept();
  const [open, setOpen] = useState(0);

  return (
    <>
      <PageHeader
        eyebrow="Verified report · external trust surface"
        title={<>The page you send when <em>the deal asks.</em></>}
        description="A live posture page communicates coverage, cadence, and remediation evidence without disclosing the open paths an attacker would want to see."
        actions={<><button className="cx-button is-ghost" onClick={() => toast("Preview opened in a new tab — visual demo")}><ExternalLink size={14} />Open public page</button><button className={`cx-toggle-button${reportPublic ? " is-on" : ""}`} onClick={() => { update({ reportPublic: !reportPublic }); toast(reportPublic ? "Report made private" : "Report is live"); }}><i /><span>{reportPublic ? "Report live" : "Report private"}</span></button></>}
      />

      <section className="cx-report-layout">
        <article className="cx-report-preview cx-reveal">
          <div className="cx-browser-bar"><span><i /><i /><i /></span><div><ShieldCheck size={12} />shiplock.dev/verified/ledgerloop</div><button onClick={() => toast("Report link copied")}><Copy size={13} /></button></div>
          <div className="cx-public-report">
            <nav><Brand compact /><span>Independent posture report</span></nav>
            <div className="cx-report-company"><span className="cx-report-company-mark">LL</span><div><p>Ledgerloop, Inc.</p><h2>Application security is continuously monitored.</h2></div><span className="cx-report-verified"><ShieldCheck size={15} />Verified</span></div>
            <div className="cx-report-rule"><span>Latest complete review</span><strong>11 minutes ago</strong><i /></div>
            <div className="cx-report-stats"><div><strong>48h</strong><span>Full audit cadence</span></div><div><strong>100%</strong><span>Pull requests reviewed</span></div><div><strong>3</strong><span>Issues closed / 30d</span></div><div><strong>0</strong><span>Criticals older than 7d</span></div></div>
            <div className="cx-report-coverage">
              <p>Observed coverage</p>
              {[
                ["Access boundaries", "Routes, identity, tenant ownership"],
                ["Sensitive data reachability", "Schemas, entries, blast radius"],
                ["Supply chain", "Dependencies and new advisories"],
                ["Payment integrity", "Webhooks and entitlement writes"],
              ].map(([title, detail]) => <div key={title}><span><Check size={12} /></span><p><strong>{title}</strong><small>{detail}</small></p></div>)}
            </div>
            <footer><span>Verified by ShipLock from selected source repositories.</span><span>No production customer data is read.</span></footer>
          </div>
        </article>

        <aside className="cx-report-controls cx-reveal">
          <div className="cx-panel">
            <div className="cx-panel-head"><div><FileCheck2 size={16} /><h2>Report controls</h2></div></div>
            <div className="cx-report-control-list">
              <div><span><strong>Public link</strong><small>shiplock.dev/verified/ledgerloop</small></span><button className="cx-icon-button" onClick={() => toast("Report link copied")}><Copy size={14} /></button></div>
              <div><span><strong>Open-risk disclosure</strong><small>Only aging threshold, never titles or evidence</small></span><em>Protected</em></div>
              <div><span><strong>Last refreshed</strong><small>After deep audit run-902</small></span><em>11m</em></div>
              <div><span><strong>Company details</strong><small>Ledgerloop, Inc. · ledgerloop.com</small></span><button>Edit</button></div>
            </div>
          </div>
          <div className="cx-report-note"><ShieldCheck size={18} /><div><strong>The report cannot expose findings.</strong><p>Its payload is deliberately separate from the private evidence shown inside the dashboard.</p></div></div>
        </aside>
      </section>

      <section className="cx-questionnaire cx-panel cx-reveal">
        <div className="cx-panel-head"><div><Sparkles size={16} /><h2>Security questionnaire drafts</h2></div><button className="cx-button is-ghost" onClick={() => toast("Questionnaire export prepared — display only")}><Download size={14} />Export all 24 answers</button></div>
        <div className="cx-questionnaire-intro"><span>Written from observed evidence</span><p>Every draft distinguishes what ShipLock can observe from what your team must attest. Review before sending.</p></div>
        <div className="cx-question-list">
          {QUESTIONNAIRE.map((item, index) => (
            <div key={item.q} className={open === index ? "is-open" : ""}>
              <button onClick={() => setOpen(open === index ? -1 : index)}><span>{String(index + 1).padStart(2, "0")}</span><strong>{item.q}</strong><ChevronDown size={15} /></button>
              <div><p>{item.a}</p><button onClick={() => { navigator.clipboard?.writeText(item.a); toast("Draft answer copied"); }}><Copy size={13} />Copy answer</button></div>
            </div>
          ))}
        </div>
        <div className="cx-questionnaire-foot"><span>20 more answers ready</span><button className="cx-text-button" onClick={() => toast("All questionnaire answers expanded")}>Review all <ArrowRight size={12} /></button></div>
      </section>
    </>
  );
}

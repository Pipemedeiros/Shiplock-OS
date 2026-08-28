"use client";

import { QUESTIONNAIRE, RESOLVED } from "../../data";
import { useStore } from "../../store";
import { Eyebrow, Mark } from "../../ui";

export default function Report() {
  const { reportPublic, set, openRisks, toast } = useStore();

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>The answer to “are you secure?”</Eyebrow>
          <h1 className="v3-serif">Report</h1>
        </div>
        <div className="v3-row">
          <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Preview opened — visual only")}>Preview</button>
          <button
            className="v3-btn v3-btn-sm v3-primary"
            onClick={() => { navigator.clipboard?.writeText("https://shiplock.dev/verified/ledgerloop"); toast("Report link copied"); }}
          >
            Copy link
          </button>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-report-head">
            <div className="v3-between">
              <span className="v3-mark" style={{ fontSize: 17 }}><Mark size={17} /> ShipLock Verified</span>
              <span className="v3-mono" style={{ fontSize: 12, color: "var(--muted-navy)" }}>shiplock.dev/verified/ledgerloop</span>
            </div>
            <h2 className="v3-serif" style={{ fontSize: 25, marginTop: 18 }}>Ledgerloop is monitored continuously.</h2>
            <p style={{ color: "var(--muted-navy)", marginTop: 8, fontSize: 14.5, maxWidth: 600 }}>
              Audited every 48 hours and on every pull request since 14 May 2026. This page is live —
              it changes when their posture changes.
            </p>
          </div>
          <div className="v3-card-p v3-grid-3">
            <div>
              <p className="v3-serif" style={{ fontSize: 27 }}>{RESOLVED.length}</p>
              <p className="v3-small">Closed in the last 30 days</p>
            </div>
            <div>
              <p className="v3-serif" style={{ fontSize: 27 }}>147</p>
              <p className="v3-small">Audits run</p>
            </div>
            <div>
              <p className="v3-serif" style={{ fontSize: 27 }}>48h</p>
              <p className="v3-small">Maximum time between audits</p>
            </div>
          </div>
          <hr className="v3-rule" />
          <div className="v3-card-p">
            <p className="v3-small">
              The public page shows cadence, coverage and what has been closed. It never shows an open
              finding — a prospect can verify you are watched without being handed a map of your gaps.
              {openRisks.length > 0 ? ` ${openRisks.length} open findings are hidden from it right now.` : ""}
            </p>
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Questionnaire answers</h2>
            <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("24 answers exported — visual only")}>Export all 24</button>
          </div>
          <div className="v3-card-p">
            <p className="v3-sub" style={{ fontSize: 14, marginBottom: 4 }}>
              Drafted from what we observed. Every answer says whether it is something we can see or
              something your team must attest to. Read them before you send them.
            </p>
            <div className="v3-qa">
              {QUESTIONNAIRE.map((q) => (
                <div key={q.question}>
                  <b>{q.question}</b>
                  <p>{q.answer}</p>
                  <span className={`v3-tag ${q.basis === "observed" ? "ok" : "warn"}`} style={{ marginTop: 8 }}>
                    {q.basis === "observed" ? "Observed by ShipLock" : "Your team must attest"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="v3-card v3-card-p v3-between">
          <div>
            <b style={{ fontWeight: 500 }}>{reportPublic ? "The report is live" : "The report is private"}</b>
            <p className="v3-small" style={{ marginTop: 3 }}>
              {reportPublic ? "Anyone with the link can see it. Rotate the link to revoke it." : "Only you can see it."}
            </p>
          </div>
          <button
            className={`v3-switch${reportPublic ? " on" : ""}`}
            onClick={() => { set({ reportPublic: !reportPublic }); toast(reportPublic ? "Report is now private" : "Report is live"); }}
            aria-label="Toggle public report"
            aria-pressed={reportPublic}
          >
            <i />
          </button>
        </div>
      </div>
    </>
  );
}

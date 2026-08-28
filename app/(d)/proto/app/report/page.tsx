"use client";

import { useState } from "react";
import { RESOLVED } from "../../data";
import { useProto } from "../../store";

const QUESTIONS = [
  { q: "Do you perform regular application security testing?",
    a: "Yes. Every pull request is statically audited before merge, and the full codebase is re-audited on a 48-hour cycle by an automated review that maps each entry point to the data it can reach. Last full audit: 11 minutes ago." },
  { q: "How do you protect customer data from access by other customers?",
    a: "Authorisation is enforced per request against the caller's organisation. Cross-tenant access is tested continuously by replaying requests as one synthetic tenant against another on a disposable copy of the schema containing no production data." },
  { q: "Are third-party dependencies monitored for known vulnerabilities?",
    a: "Yes. Dependencies are re-checked against new advisories daily and on every pull request, independently of whether the team ships that day." },
  { q: "Who can access the production database?",
    a: "Named engineers only, through the provider's access control. ShipLock itself holds read-only repository access and never reads production data." },
];

export default function ReportPage() {
  const { openPaths, reportPublic, set, toast } = useProto();
  const [copied, setCopied] = useState<string | null>(null);

  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Report</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>The page you send when someone asks.</h1>
          <p className="pr-sub" style={{ marginTop: 8, maxWidth: 620 }}>
            A live posture page at a link you control. It says what is monitored and when it last
            ran. It never lists an open finding — that is your business, not your prospect&apos;s.
          </p>
        </div>
        <button
          className={`pr-btn pr-btn-sm ${reportPublic ? "pr-btn-primary" : "pr-btn-ghost"}`}
          onClick={() => { set({ reportPublic: !reportPublic }); toast(reportPublic ? "Report is now private" : "Report is live at shiplock.dev/verified/ledgerloop"); }}
        >
          {reportPublic ? "Live" : "Private"}
        </button>
      </div>

      <div className="pr-stack">
        <div className="pr-card">
          <div className="pr-hd">
            <h3 className="pr-eyebrow">shiplock.dev/verified/ledgerloop</h3>
            <button className="pr-btn pr-btn-ghost pr-btn-sm"
              onClick={() => { navigator.clipboard?.writeText("https://shiplock.dev/verified/ledgerloop"); toast("Link copied"); }}>
              Copy link
            </button>
          </div>
          <div className="pr-card-p" style={{ background: "var(--porcelain)" }}>
            <div className="pr-card pr-card-p" style={{ maxWidth: 640, margin: "0 auto" }}>
              <div className="pr-between">
                <strong className="pr-serif" style={{ fontSize: 20 }}>Ledgerloop</strong>
                <span className="pr-tag pr-tag-ok">Monitored</span>
              </div>
              <p className="pr-sub" style={{ marginTop: 6, fontSize: 13.5 }}>
                Independent, continuous application security review by ShipLock.
              </p>
              <hr className="pr-rule" style={{ margin: "16px 0" }} />
              <div className="pr-stack" style={{ gap: 10, fontSize: 14 }}>
                <Row k="Last full audit" v="11 minutes ago" />
                <Row k="Audit cadence" v="Every pull request · deep audit every 48 hours" />
                <Row k="Coverage" v="Access control · data exposure · dependencies · payment integrity · secrets" />
                <Row k="Issues closed, last 30 days" v={`${RESOLVED.length}`} />
                <Row k="Critical findings older than 7 days" v={openPaths.length ? "1 — remediation in progress" : "None"} />
              </div>
              <p className="pr-sub" style={{ fontSize: 12, marginTop: 16 }}>
                ShipLock holds read-only access to source code. It does not read customer data.
              </p>
            </div>
          </div>
        </div>

        <div className="pr-card">
          <div className="pr-hd">
            <h3 className="pr-eyebrow">Security questionnaire · draft answers</h3>
            <span className="pr-sub" style={{ fontSize: 13 }}>Written from what we actually observe. Edit before you send.</span>
          </div>
          <div className="pr-card-p pr-stack">
            {QUESTIONS.map((item) => (
              <div key={item.q} className="pr-stack" style={{ gap: 6 }}>
                <div className="pr-between">
                  <strong style={{ fontWeight: 500, fontSize: 14.5 }}>{item.q}</strong>
                  <button className="pr-btn pr-btn-ghost pr-btn-sm"
                    onClick={() => { navigator.clipboard?.writeText(item.a); setCopied(item.q); toast("Answer copied"); }}>
                    {copied === item.q ? "Copied" : "Copy"}
                  </button>
                </div>
                <p className="pr-sub" style={{ fontSize: 14 }}>{item.a}</p>
                <hr className="pr-rule" />
              </div>
            ))}
            <button className="pr-btn pr-btn-primary pr-btn-sm" style={{ alignSelf: "flex-start" }}
              onClick={() => toast("Exported 24 answers as a filled SIG Lite workbook")}>
              Export the whole questionnaire
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="pr-between">
      <span className="pr-sub">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}

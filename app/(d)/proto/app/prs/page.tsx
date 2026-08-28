"use client";

import { PULLS } from "../../data";
import { useProto } from "../../store";

export default function PullsPage() {
  const { blockMerges, set, toast } = useProto();
  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Pull requests</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>Audited before it lands, not after.</h1>
        </div>
        <button
          className={`pr-btn pr-btn-sm ${blockMerges ? "pr-btn-primary" : "pr-btn-ghost"}`}
          onClick={() => { set({ blockMerges: !blockMerges }); toast(blockMerges ? "Now advisory only — merges are never blocked" : "Critical findings will block a merge"); }}
        >
          {blockMerges ? "Blocking merges on critical" : "Advisory only"}
        </button>
      </div>

      <div className="pr-card">
        <table className="pr-table">
          <thead>
            <tr><th>PR</th><th>Verdict</th><th>Author</th><th style={{ textAlign: "right" }}>Check</th></tr>
          </thead>
          <tbody>
            {PULLS.map((p) => (
              <tr key={p.n}>
                <td>
                  <span className="pr-mono" style={{ color: "var(--muted)" }}>#{p.n}</span>{" "}
                  <strong style={{ fontWeight: 500 }}>{p.title}</strong>
                  <div className="pr-sub" style={{ fontSize: 12.5 }}>{p.when}</div>
                </td>
                <td className="pr-sub" style={{ maxWidth: 340 }}>{p.verdict}</td>
                <td className="pr-mono" style={{ fontSize: 12.5 }}>{p.author}</td>
                <td style={{ textAlign: "right" }}>
                  <span className={`pr-tag ${p.state === "blocked" ? "pr-tag-crit" : p.state === "warned" ? "pr-tag-warn" : "pr-tag-ok"}`}>
                    {p.state === "blocked" ? (blockMerges ? "Blocked" : "Critical") : p.state === "warned" ? "Warned" : p.state === "ours" ? "Ours" : "Passed"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="pr-card pr-card-p" style={{ marginTop: 16 }}>
        <p className="pr-eyebrow">What the check comments on your PR</p>
        <div className="pr-code" style={{ marginTop: 12 }}>{`ShipLock · 1 critical path introduced

GET /api/invoices/export resolves a user with auth() but never compares
orgId to invoices.workspaceId — the same gap as path SL-1 on main.

  app/api/invoices/export/route.ts:22

Reproduced on a disposable copy of your schema: workspace A read
workspace B's rows. Suggested change is on branch shiplock/export-scope.`}</div>
      </div>
    </>
  );
}

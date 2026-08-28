"use client";

import {
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  FileDiff,
  GitCommitHorizontal,
  GitPullRequestArrow,
  MessageSquareText,
  ShieldAlert,
  UserRound,
} from "lucide-react";
import { useState } from "react";
import { PULL_REQUESTS } from "../../data";
import { useConcept } from "../../store";
import { PageHeader, StatusPill } from "../../ui";

export default function PullRequestsPage() {
  const { mergeBlocking, update, toast } = useConcept();
  const [selected, setSelected] = useState(PULL_REQUESTS[0]);

  return (
    <>
      <PageHeader
        eyebrow="Pull request guard · before merge"
        title={<>Review what changed, <em>not the whole world again.</em></>}
        description="Each pull request is checked against the existing application map. New paths are explained in the language of the codebase and traced back to the current open risk."
        actions={<button className={`cx-toggle-button${mergeBlocking ? " is-on" : ""}`} onClick={() => { update({ mergeBlocking: !mergeBlocking }); toast(mergeBlocking ? "Merge blocking disabled" : "Critical paths will block merges"); }}><i /><span>{mergeBlocking ? "Blocking critical merges" : "Advisory only"}</span></button>}
      />

      <section className="cx-pr-layout">
        <div className="cx-pr-table cx-panel cx-reveal">
          <div className="cx-panel-head"><div><GitPullRequestArrow size={16} /><h2>Recent pull requests</h2></div><span>5 of 68 this month</span></div>
          <div className="cx-pr-table-head"><span>Pull request</span><span>Change</span><span>Author</span><span>Verdict</span></div>
          {PULL_REQUESTS.map((pull) => (
            <button key={pull.number} className={selected.number === pull.number ? "is-selected" : ""} onClick={() => setSelected(pull)}>
              <span className="cx-pr-title"><i className={`is-${pull.state}`}>{pull.state === "clear" || pull.state === "ours" ? <Check size={13} /> : "!"}</i><span><strong>#{pull.number} {pull.title}</strong><small>{pull.branch} · {pull.time} ago</small></span></span>
              <span className="cx-pr-delta"><strong>{pull.delta}</strong><small>{pull.files} files</small></span>
              <span className="cx-pr-author"><i>{pull.avatar}</i><span>{pull.author}</span></span>
              <span><StatusPill tone={pull.state === "blocked" ? "signal" : pull.state === "warning" ? "attention" : pull.state === "ours" ? "bronze" : "verified"}>{pull.state === "ours" ? "fix ready" : pull.state}</StatusPill></span>
            </button>
          ))}
        </div>

        <aside className="cx-pr-review cx-panel cx-reveal">
          <div className="cx-pr-review-head">
            <div><span className={`cx-pr-big-state is-${selected.state}`}>{selected.state === "clear" || selected.state === "ours" ? <CheckCircle2 size={22} /> : <ShieldAlert size={22} />}</span><span><small>ShipLock check</small><strong>{selected.state === "blocked" ? "Merge blocked" : selected.state === "warning" ? "Review advised" : selected.state === "ours" ? "Validated fix" : "Clear to merge"}</strong></span></div>
            <span>{selected.time} ago</span>
          </div>
          <div className="cx-pr-review-body">
            <div className="cx-pr-review-title"><span>#{selected.number}</span><h2>{selected.title}</h2><p>{selected.verdict}</p></div>

            {selected.state === "blocked" ? (
              <div className="cx-pr-comment">
                <div><span className="cx-brand-avatar">SL</span><strong>shiplock-bot</strong><small>commented just now</small></div>
                <p><strong>1 critical path introduced.</strong> The export handler resolves a signed-in user but never scopes invoice rows to that user’s active workspace.</p>
                <div className="cx-comment-path"><span>GET /api/invoices/export</span><i /><span className="is-break">workspace scope</span><i /><span>all invoices</span></div>
                <pre><code><span>22</span>const invoices = await db.query.invoices.findMany();</code><code className="is-add"><span>23</span>where: eq(invoices.workspaceId, orgId)</code></pre>
                <div className="cx-comment-proof"><Check size={13} /><span><strong>Reproduced on a disposable environment</strong><small>Workspace A received workspace B’s export rows.</small></span></div>
              </div>
            ) : (
              <div className="cx-pr-clear-state"><CheckCircle2 size={34} /><h3>No new reachable path</h3><p>{selected.verdict}. Existing path status is unchanged.</p></div>
            )}

            <div className="cx-pr-checks">
              <p className="cx-panel-label">Check execution</p>
              <div><GitCommitHorizontal size={15} /><span><strong>Diff mapped</strong><small>{selected.files} files · {selected.delta}</small></span><em>8s</em></div>
              <div><FileDiff size={15} /><span><strong>Reachability compared</strong><small>2 entries changed · 1 asset touched</small></span><em>19s</em></div>
              <div><MessageSquareText size={15} /><span><strong>Verdict written</strong><small>Evidence attached to this commit</small></span><em>31s</em></div>
            </div>
          </div>
          <div className="cx-pr-review-foot"><span><Clock3 size={13} />Completed in 38 seconds</span><button className="cx-button is-dark" onClick={() => toast("Opening GitHub check — visual demo")}>Open on GitHub <ArrowRight size={13} /></button></div>
        </aside>
      </section>

      <section className="cx-pr-summary cx-reveal">
        <div><UserRound size={18} /><span><strong>Unlimited teammates</strong><small>Security follows the code, not the seat count.</small></span></div>
        <div><GitPullRequestArrow size={18} /><span><strong>68 / 200 PR audits</strong><small>34% of this month’s included volume.</small></span></div>
        <div><ShieldAlert size={18} /><span><strong>2 merges protected</strong><small>Critical paths stopped before production.</small></span></div>
      </section>
    </>
  );
}

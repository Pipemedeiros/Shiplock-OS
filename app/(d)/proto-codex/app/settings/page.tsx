"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronRight,
  CreditCard,
  Database,
  GitBranch,
  Mail,
  RefreshCcw,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
} from "lucide-react";
import { useConcept } from "../../store";
import { PageHeader, StatusPill } from "../../ui";

export default function SettingsPage() {
  const {
    mergeBlocking,
    automaticFixes,
    emailAlerts,
    databaseConnected,
    update,
    reset,
    toast,
  } = useConcept();

  return (
    <>
      <PageHeader
        eyebrow="Settings · workspace controls"
        title={<>Connections, behavior, <em>and the kill switch.</em></>}
        description="Every control states its blast radius. Demo actions update this concept only and never call an external service."
      />

      <section className="cx-settings-grid">
        <div className="cx-settings-main">
          <article className="cx-settings-section cx-panel cx-reveal">
            <div className="cx-panel-head"><div><GitBranch size={16} /><h2>Source connection</h2></div><StatusPill tone="verified">healthy</StatusPill></div>
            <div className="cx-connection-row">
              <span className="cx-connection-icon is-github"><GitBranch size={21} /></span>
              <span><strong>ledgerloop</strong><small>GitHub App · 3 repositories selected · read-only source access</small></span>
              <button className="cx-button is-ghost">Manage <ChevronRight size={13} /></button>
            </div>
            <div className="cx-connection-meta"><span><Check size={12} />Last synchronized 8m ago</span><span><Check size={12} />Webhook healthy</span><span><Check size={12} />Default branch main</span></div>
          </article>

          <article className="cx-settings-section cx-panel cx-reveal">
            <div className="cx-panel-head"><div><Database size={16} /><h2>Optional evidence</h2></div><span>Not required</span></div>
            <div className="cx-connection-row">
              <span className={`cx-connection-icon${databaseConnected ? " is-connected" : ""}`}><Database size={21} /></span>
              <span><strong>Database policy evidence</strong><small>{databaseConnected ? "Read-only evidence connected. Selected inferred paths can now be corroborated." : "Observe provider-side policy to deepen selected findings. GitHub remains enough to use the product."}</small></span>
              <button className={`cx-button ${databaseConnected ? "is-ghost" : "is-dark"}`} onClick={() => { update({ databaseConnected: !databaseConnected }); toast(databaseConnected ? "Optional evidence disconnected" : "Optional evidence connected — visual demo"); }}>{databaseConnected ? "Disconnect" : "Connect"}</button>
            </div>
          </article>

          <article className="cx-settings-section cx-panel cx-reveal">
            <div className="cx-panel-head"><div><SlidersHorizontal size={16} /><h2>Behavior</h2></div><span>Workspace-wide</span></div>
            <div className="cx-setting-list">
              <SettingToggle label="Block merges on a new critical path" detail="The ShipLock check fails. Your GitHub branch protection decides whether that stops the merge." value={mergeBlocking} onChange={() => update({ mergeBlocking: !mergeBlocking })} />
              <SettingToggle label="Open validated fix pull requests" detail="Only after reproduction, attack-stop, and legitimate-flow gates pass. Always a new branch; never merged by ShipLock." value={automaticFixes} onChange={() => update({ automaticFixes: !automaticFixes })} />
              <SettingToggle label="Email only on new critical paths" detail="No clean-scan email and no repeated alert for an unchanged finding. Silence means no new work." value={emailAlerts} onChange={() => update({ emailAlerts: !emailAlerts })} />
            </div>
          </article>

          <article className="cx-kill-switch cx-reveal">
            <div><span><AlertTriangle size={18} /></span><div><strong>Monitor only. Never act.</strong><p>Stops fix branches and merge checks for this workspace. Audits continue and evidence remains visible.</p></div></div>
            <button className="cx-button is-danger" onClick={() => toast("Kill switch armed — concept only")}>Arm kill switch</button>
          </article>
        </div>

        <aside className="cx-settings-side">
          <article className="cx-plan-card cx-reveal">
            <div className="cx-plan-card-top"><span>Current plan</span><StatusPill tone="bronze">Startup</StatusPill></div>
            <div className="cx-plan-price"><strong>$319</strong><span>/month<br />billed annually</span></div>
            <div className="cx-plan-usage">
              <Usage label="Repositories" value="3 / 5" pct={60} />
              <Usage label="Lines under audit" value="171k / 250k" pct={68} />
              <Usage label="PR audits" value="68 / 200" pct={34} />
            </div>
            <button className="cx-button is-ghost-light"><CreditCard size={14} />Manage plan</button>
            <p>Next invoice September 25 · teammates unlimited</p>
          </article>

          <article className="cx-settings-mini cx-panel cx-reveal">
            <div><Mail size={17} /><span><strong>felipe@ledgerloop.com</strong><small>Owner · alert recipient</small></span></div>
            <button>Manage team <ChevronRight size={13} /></button>
          </article>

          <article className="cx-settings-mini cx-panel cx-reveal">
            <div><ShieldCheck size={17} /><span><strong>Evidence retention</strong><small>90 days · source checkout deleted after run</small></span></div>
            <button>Review policy <ChevronRight size={13} /></button>
          </article>

          <article className="cx-demo-reset cx-reveal">
            <div><RefreshCcw size={16} /><span><strong>Reset this visual concept</strong><small>Restore every toggle and dismissed path.</small></span></div>
            <button onClick={() => { reset(); toast("Concept state reset"); }}><Trash2 size={13} />Reset</button>
          </article>

          <Link href="/proto-codex" className="cx-back-concept"><ArrowLeft size={13} />Back to concept overview</Link>
        </aside>
      </section>
    </>
  );
}

function SettingToggle({ label, detail, value, onChange }: { label: string; detail: string; value: boolean; onChange: () => void }) {
  return (
    <div><span><strong>{label}</strong><small>{detail}</small></span><button className={`cx-switch${value ? " is-on" : ""}`} onClick={onChange} aria-pressed={value}><i /></button></div>
  );
}

function Usage({ label, value, pct }: { label: string; value: string; pct: number }) {
  return <div><span><strong>{label}</strong><small>{value}</small></span><div><i style={{ width: `${pct}%` }} /></div></div>;
}

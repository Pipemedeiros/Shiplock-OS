"use client";

import Link from "next/link";
import { PROTO_PLANS } from "../../data";
import { useProto } from "../../store";

export default function SettingsPage() {
  const { plan, billing, set, slack, blockMerges, reset, toast, repos } = useProto();
  const current = PROTO_PLANS.find((p) => p.id === plan) ?? PROTO_PLANS[1];
  const price = billing === "annual" ? current.annualMonthly : current.monthly;

  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Settings</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>Plan, connections, alerts.</h1>
        </div>
      </div>

      <div className="pr-stack">
        <div className="pr-card">
          <div className="pr-hd">
            <h3 className="pr-eyebrow">Plan</h3>
            <div className="pr-toggle">
              <button className={billing === "monthly" ? "on" : ""} onClick={() => set({ billing: "monthly" })}>Monthly</button>
              <button className={billing === "annual" ? "on" : ""} onClick={() => set({ billing: "annual" })}>Annual</button>
            </div>
          </div>
          <div className="pr-card-p pr-stack">
            <div className="pr-between">
              <div>
                <strong className="pr-serif" style={{ fontSize: 22 }}>{current.name}</strong>
                <p className="pr-sub" style={{ fontSize: 13.5 }}>{current.who}</p>
              </div>
              <div style={{ textAlign: "right" }}>
                <div className="pr-serif" style={{ fontSize: 24 }}>${price.toLocaleString()}<span className="pr-sub" style={{ fontSize: 13 }}>/mo</span></div>
                <div className="pr-sub" style={{ fontSize: 12.5 }}>{billing === "annual" ? "billed annually" : "billed monthly"}</div>
              </div>
            </div>
            <hr className="pr-rule" />
            <div className="pr-stack" style={{ gap: 10 }}>
              <Usage label="Repositories" used={repos.length} cap={plan === "solo" ? 1 : plan === "startup" ? 5 : 20} />
              <Usage label="Pull-request audits this month" used={68} cap={plan === "solo" ? 30 : plan === "startup" ? 200 : 750} />
              <Usage label="Lines of code under audit" used={171} cap={plan === "solo" ? 50 : plan === "startup" ? 250 : 1500} suffix="k" />
            </div>
            <div className="pr-wrap">
              {PROTO_PLANS.map((p) => (
                <button key={p.id}
                  className={`pr-btn pr-btn-sm ${p.id === plan ? "pr-btn-primary" : "pr-btn-ghost"}`}
                  onClick={() => { set({ plan: p.id }); toast(`Switched to ${p.name} — prorated on your next invoice`); }}>
                  {p.name}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="pr-grid-2">
          <div className="pr-card">
            <div className="pr-hd"><h3 className="pr-eyebrow">Connections</h3></div>
            <div className="pr-card-p pr-stack" style={{ gap: 14 }}>
              <div className="pr-between">
                <div>
                  <strong style={{ fontWeight: 500 }}>GitHub</strong>
                  <p className="pr-sub" style={{ fontSize: 13 }}>ledgerloop · {repos.length} repositories · read-only</p>
                </div>
                <span className="pr-tag pr-tag-ok">Required</span>
              </div>
              <hr className="pr-rule" />
              <div className="pr-between">
                <div>
                  <strong style={{ fontWeight: 500 }}>Your database, read-only</strong>
                  <p className="pr-sub" style={{ fontSize: 13 }}>Turns inferred findings into proven ones. Optional.</p>
                </div>
                <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={() => toast("Not required — the product works on GitHub alone")}>Connect</button>
              </div>
              <hr className="pr-rule" />
              <div className="pr-between">
                <div>
                  <strong style={{ fontWeight: 500 }}>Slack</strong>
                  <p className="pr-sub" style={{ fontSize: 13 }}>New critical paths only. Silence means clean.</p>
                </div>
                <button className={`pr-btn pr-btn-sm ${slack ? "pr-btn-primary" : "pr-btn-ghost"}`}
                  onClick={() => { set({ slack: !slack }); toast(slack ? "Slack disconnected" : "Posting to #eng-alerts"); }}>
                  {slack ? "Connected" : "Connect"}
                </button>
              </div>
            </div>
          </div>

          <div className="pr-card">
            <div className="pr-hd"><h3 className="pr-eyebrow">Behaviour</h3></div>
            <div className="pr-card-p pr-stack" style={{ gap: 14 }}>
              <Toggle
                label="Block merges on a new critical path"
                note="The check fails. Your branch protection decides whether that stops the merge."
                on={blockMerges}
                onClick={() => set({ blockMerges: !blockMerges })}
              />
              <hr className="pr-rule" />
              <Toggle
                label="Open fix pull requests automatically"
                note="Only for fixes that passed all three validation gates. Always a new branch, never merged by us."
                on
                onClick={() => toast("Fix PRs stay on — they are the product")}
              />
              <hr className="pr-rule" />
              <Toggle
                label="Never act, only report"
                note="The kill switch. No pull requests, no checks, no writes of any kind."
                on={false}
                onClick={() => toast("Kill switch armed for this workspace")}
              />
            </div>
          </div>
        </div>

        <div className="pr-between">
          <Link href="/proto" className="pr-btn pr-btn-ghost pr-btn-sm">← Back to the pitch</Link>
          <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={() => { reset(); toast("Prototype reset"); }}>
            Reset the demo
          </button>
        </div>
      </div>
    </>
  );
}

function Usage({ label, used, cap, suffix = "" }: { label: string; used: number; cap: number; suffix?: string }) {
  const pct = Math.min(100, (used / cap) * 100);
  return (
    <div>
      <div className="pr-between" style={{ fontSize: 13.5 }}>
        <span>{label}</span>
        <span className="pr-mono" style={{ color: pct > 100 ? "var(--crit)" : "var(--muted)", fontSize: 12.5 }}>
          {used}{suffix} / {cap}{suffix}
        </span>
      </div>
      <div className="pr-bar" style={{ marginTop: 6 }}>
        <i style={{ width: `${pct}%`, background: pct > 90 ? "var(--warn)" : "var(--bronze)" }} />
      </div>
    </div>
  );
}

function Toggle({ label, note, on, onClick }: { label: string; note: string; on: boolean; onClick: () => void }) {
  return (
    <div className="pr-between" style={{ alignItems: "flex-start" }}>
      <div style={{ maxWidth: 340 }}>
        <strong style={{ fontWeight: 500 }}>{label}</strong>
        <p className="pr-sub" style={{ fontSize: 13 }}>{note}</p>
      </div>
      <button className={`pr-btn pr-btn-sm ${on ? "pr-btn-primary" : "pr-btn-ghost"}`} onClick={onClick}>
        {on ? "On" : "Off"}
      </button>
    </div>
  );
}

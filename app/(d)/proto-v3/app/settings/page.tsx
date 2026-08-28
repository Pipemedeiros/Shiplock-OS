"use client";

import { useStore } from "../../store";
import { Eyebrow } from "../../ui";

export default function Settings() {
  const { blockMerges, autoFix, emailAlerts, paused, repos, set, reset, toast } = useStore();

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>Connections, behaviour, billing</Eyebrow>
          <h1 className="v3-serif">Settings</h1>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">Connection</h2><span className="v3-tag ok">GitHub connected</span></div>
          <div className="v3-card-p">
            <div className="v3-setting">
              <div>
                <b>ledgerloop</b>
                <small>{repos.join(" · ")} · read-only on contents</small>
              </div>
              <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Repository picker — visual only")}>Change repositories</button>
            </div>
            <div className="v3-setting">
              <div>
                <b>Database — optional</b>
                <small>A read-only role raises findings from inferred to proven. Not required, and nothing is withheld without it.</small>
              </div>
              <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Connect a read-only role — visual only")}>Connect</button>
            </div>
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">What we do on our own</h2></div>
          <div className="v3-card-p">
            <Toggle
              label="Block a merge that reintroduces a fixed finding"
              detail="Posts a failing check on the pull request. You can always merge anyway."
              on={blockMerges}
              onChange={() => { set({ blockMerges: !blockMerges }); toast(blockMerges ? "Merge blocking off" : "Merge blocking on"); }}
            />
            <Toggle
              label="Prepare fix pull requests"
              detail="Opened on their own branch, only after all three checks pass. We never merge them."
              on={autoFix}
              onChange={() => { set({ autoFix: !autoFix }); toast(autoFix ? "Fix PRs off" : "Fix PRs on"); }}
            />
            <Toggle
              label="Email me when something new appears"
              detail="New findings only. We never email about a finding you have already seen."
              on={emailAlerts}
              onChange={() => { set({ emailAlerts: !emailAlerts }); toast(emailAlerts ? "Emails off" : "Emails on"); }}
            />
            <div className="v3-setting">
              <div>
                <b>Monitor only — never act</b>
                <small>We keep auditing and telling you, and change nothing anywhere, ever. This overrides everything above.</small>
              </div>
              <button
                className={`v3-switch${paused ? " on" : ""}`}
                onClick={() => { set({ paused: !paused }); toast(paused ? "ShipLock may act again" : "Monitor only — nothing will be changed"); }}
                aria-label="Monitor only"
                aria-pressed={paused}
              >
                <i />
              </button>
            </div>
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">Plan</h2><span className="v3-small">Startup · annual</span></div>
          <div className="v3-card-p">
            <div className="v3-setting">
              <div>
                <b>$319 a month, billed annually</b>
                <small>2 of 5 repositories · 162k of 250k lines · 84 of 200 pull-request audits this month</small>
              </div>
              <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Billing portal — visual only")}>Manage billing</button>
            </div>
            <div className="v3-setting">
              <div>
                <b>Teammates</b>
                <small>Unlimited and free on every plan. We charge for code read, not for people.</small>
              </div>
              <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast("Invite — visual only")}>Invite</button>
            </div>
          </div>
        </div>

        <div className="v3-card v3-card-p v3-between">
          <div>
            <b style={{ fontWeight: 500 }}>Reset the demo</b>
            <p className="v3-small" style={{ marginTop: 3 }}>Puts every finding back and clears what this browser remembered.</p>
          </div>
          <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => { reset(); toast("Demo reset"); }}>Reset</button>
        </div>
      </div>
    </>
  );
}

function Toggle({ label, detail, on, onChange }: { label: string; detail: string; on: boolean; onChange: () => void }) {
  return (
    <div className="v3-setting">
      <div>
        <b>{label}</b>
        <small>{detail}</small>
      </div>
      <button className={`v3-switch${on ? " on" : ""}`} onClick={onChange} aria-label={label} aria-pressed={on}>
        <i />
      </button>
    </div>
  );
}

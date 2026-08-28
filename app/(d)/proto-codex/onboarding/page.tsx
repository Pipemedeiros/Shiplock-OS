"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  GitBranch,
  GitPullRequestArrow,
  LockKeyhole,
  Play,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { RISKS, TRACE } from "../data";
import { Brand, RunGlyph } from "../ui";

const REPOSITORIES = [
  { name: "ledgerloop/app", language: "TypeScript", meta: "138k lines · pushed 2h ago", recommended: true },
  { name: "ledgerloop/workers", language: "TypeScript", meta: "24k lines · pushed yesterday", recommended: true },
  { name: "ledgerloop/marketing", language: "TypeScript", meta: "9k lines · pushed 5d ago", recommended: false },
  { name: "ledgerloop/infra", language: "HCL", meta: "6k lines · pushed 3w ago", recommended: false },
];

export default function OnboardingPage() {
  const [step, setStep] = useState(0);
  const [selected, setSelected] = useState(["ledgerloop/app", "ledgerloop/workers"]);
  const [authorizing, setAuthorizing] = useState(false);

  return (
    <div className="cx-onboarding">
      <header className="cx-onboard-header">
        <Link href="/proto-codex"><Brand /></Link>
        <div className="cx-stepper" aria-label={`Step ${step + 1} of 3`}>
          {["Connect", "Choose repositories", "First audit"].map((label, index) => (
            <div key={label} className={`${index === step ? "is-active" : ""}${index < step ? " is-done" : ""}`}>
              <span>{index < step ? <Check size={12} /> : index + 1}</span><small>{label}</small>
            </div>
          ))}
        </div>
        <Link href="/proto-codex/app" className="cx-text-link">Skip to dashboard <ArrowRight size={13} /></Link>
      </header>

      <main className="cx-onboard-main">
        {step === 0 ? (
          <section className="cx-onboard-stage cx-reveal">
            <div className="cx-onboard-copy">
              <p className="cx-kicker"><span>01 · Establish the map</span></p>
              <h1>Start with the one place that already declares your system.</h1>
              <p>Choose exactly which repositories ShipLock can read. The concept keeps the permission model visible before the button, not after it.</p>
              <div className="cx-permission-list">
                <div><LockKeyhole size={17} /><span><strong>Repository contents</strong><small>Read-only on the branches you select</small></span><em>read</em></div>
                <div><GitPullRequestArrow size={17} /><span><strong>Pull requests</strong><small>Inspect diffs and open fix branches</small></span><em>read / write</em></div>
                <div><ShieldCheck size={17} /><span><strong>Status checks</strong><small>Report a security verdict before merge</small></span><em>write</em></div>
              </div>
              <button
                className="cx-button is-bronze is-large"
                disabled={authorizing}
                onClick={() => {
                  setAuthorizing(true);
                  window.setTimeout(() => { setAuthorizing(false); setStep(1); }, 900);
                }}
              >
                {authorizing ? <><span className="cx-spinner" />Opening GitHub…</> : <><GitBranch size={17} />Install the GitHub App</>}
              </button>
              <small className="cx-privacy-note">Revoke at any time. This visual prototype never leaves your browser.</small>
            </div>
            <OnboardingVisual />
          </section>
        ) : null}

        {step === 1 ? (
          <section className="cx-repo-stage cx-reveal">
            <div className="cx-stage-heading">
              <p className="cx-kicker"><span>02 · Set the production boundary</span></p>
              <h1>Which repositories ship the product?</h1>
              <p>The interface suggests likely production repositories from manifests and deployment configuration. You have the final word.</p>
            </div>
            <div className="cx-repo-list">
              {REPOSITORIES.map((repository) => {
                const checked = selected.includes(repository.name);
                return (
                  <button
                    key={repository.name}
                    className={checked ? "is-selected" : ""}
                    onClick={() => setSelected((current) => checked ? current.filter((item) => item !== repository.name) : [...current, repository.name])}
                  >
                    <span className="cx-check-box">{checked ? <Check size={14} /> : null}</span>
                    <span className="cx-repo-avatar">{repository.name.split("/")[1].slice(0, 2).toUpperCase()}</span>
                    <span className="cx-repo-detail"><strong>{repository.name}</strong><small><i />{repository.language} · {repository.meta}</small></span>
                    {repository.recommended ? <em>Suggested</em> : null}
                  </button>
                );
              })}
            </div>
            <div className="cx-stage-actions">
              <button className="cx-button is-ghost" onClick={() => setStep(0)}><ArrowLeft size={14} />Back</button>
              <span>{selected.length} selected · estimated first audit 4–6 minutes</span>
              <button className="cx-button is-bronze" disabled={!selected.length} onClick={() => setStep(2)}><Play size={14} />Run first audit</button>
            </div>
          </section>
        ) : null}

        {step === 2 ? <LiveAudit selected={selected} /> : null}
      </main>
    </div>
  );
}

function OnboardingVisual() {
  return (
    <div className="cx-onboard-visual" aria-hidden="true">
      <div className="cx-code-map">
        <div className="cx-map-file is-one"><span>route.ts</span><i /><i /><i /></div>
        <div className="cx-map-file is-two"><span>schema.ts</span><i /><i /><i /></div>
        <div className="cx-map-file is-three"><span>middleware.ts</span><i /><i /></div>
        <svg viewBox="0 0 500 360">
          <path d="M95 90 C180 90 150 180 245 180 S315 270 405 270" />
          <path d="M88 265 C160 265 160 180 245 180 S320 92 412 92" />
          <circle cx="245" cy="180" r="7" />
        </svg>
        <div className="cx-map-core"><span><GitBranch size={22} /></span><strong>One repository</strong><small>becomes a system map</small></div>
        <div className="cx-map-tag is-auth">Identity</div>
        <div className="cx-map-tag is-data">Data</div>
        <div className="cx-map-tag is-entry">Entries</div>
        <div className="cx-map-pulse" />
      </div>
    </div>
  );
}

function LiveAudit({ selected }: { selected: string[] }) {
  const router = useRouter();
  const [shown, setShown] = useState(1);
  const [paused, setPaused] = useState(false);
  const complete = shown >= TRACE.length;

  useEffect(() => {
    if (paused || complete) return;
    const timer = window.setTimeout(() => setShown((count) => count + 1), 640);
    return () => window.clearTimeout(timer);
  }, [shown, paused, complete]);

  const alertCount = useMemo(() => TRACE.slice(0, shown).filter((item) => item.alert).length, [shown]);
  const progress = Math.round((shown / TRACE.length) * 100);

  return (
    <section className="cx-audit-stage cx-reveal">
      <div className="cx-stage-heading is-audit">
        <p className="cx-kicker"><span>03 · First audit</span><i className={complete ? "is-done" : ""}>{complete ? "Complete" : "Running live"}</i></p>
        <h1>{complete ? "The map is ready." : "Reading the application from its edges inward."}</h1>
        <p>{selected.join(" + ")} · read-only checkout · sample trace</p>
      </div>

      <div className="cx-audit-console">
        <div className="cx-console-top">
          <div><span className={`cx-status-dot ${complete ? "is-verified" : "is-bronze"}`} /><strong>{complete ? "Audit complete" : "Audit in progress"}</strong></div>
          <div><span>{alertCount} paths surfaced</span><strong>{progress}%</strong></div>
        </div>
        <div className="cx-progress"><i style={{ width: `${progress}%` }} /></div>
        <div className="cx-console-grid">
          <div className="cx-console-trace">
            {TRACE.slice(0, shown).map((step, index) => (
              <div className={`cx-console-line${step.alert ? " is-alert" : ""}`} key={`${step.time}-${step.label}`} style={{ "--delay": `${index * 40}ms` } as React.CSSProperties}>
                <time>{step.time}</time>
                <span className="cx-console-icon"><RunGlyph phase={step.phase} alert={step.alert} /></span>
                <span><strong>{step.label}</strong><small>{step.note}</small></span>
              </div>
            ))}
          </div>
          <aside className="cx-audit-vitals">
            <div><span>Entries mapped</span><strong>{Math.min(63, shown * 8)}</strong></div>
            <div><span>Assets reached</span><strong>{Math.min(24, shown * 3)}</strong></div>
            <div><span>Paths open</span><strong className="is-signal">{Math.min(RISKS.length, alertCount + (complete ? 1 : 0))}</strong></div>
            <div><span>Proof environments</span><strong>{shown > 5 ? 1 : 0}</strong></div>
            <div className="cx-vital-orbit"><span /><i /><em /></div>
          </aside>
        </div>
      </div>

      <div className="cx-stage-actions">
        {!complete ? <button className="cx-button is-ghost" onClick={() => setPaused(!paused)}>{paused ? "Resume" : "Pause"} animation</button> : <span><CheckCircle2 size={16} />Disposable environment destroyed. No customer data was read.</span>}
        <button className="cx-button is-bronze" onClick={() => complete ? router.push("/proto-codex/app") : setShown(TRACE.length)}>
          {complete ? <>Open dashboard <ArrowRight size={14} /></> : "Finish now"}
        </button>
      </div>
    </section>
  );
}

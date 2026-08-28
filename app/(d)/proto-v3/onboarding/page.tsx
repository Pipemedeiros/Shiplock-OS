"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Check, GitPullRequest, LockKeyhole, ShieldCheck } from "lucide-react";
import { RISKS, TRACE } from "../data";
import { useStore } from "../store";
import { Eyebrow, Mark } from "../ui";

const REPOS = [
  { name: "ledgerloop/app", meta: "TypeScript · 138k lines · pushed 2h ago", suggested: true },
  { name: "ledgerloop/workers", meta: "TypeScript · 24k lines · pushed yesterday", suggested: true },
  { name: "ledgerloop/marketing", meta: "TypeScript · 9k lines · pushed 5d ago", suggested: false },
  { name: "ledgerloop/infra", meta: "HCL · 6k lines · pushed 3w ago", suggested: false },
];

const STEPS = ["Connect", "Choose repositories", "First audit"];

export default function Onboarding() {
  const router = useRouter();
  const { set, toast } = useStore();
  const [step, setStep] = useState(0);
  const [installing, setInstalling] = useState(false);
  const [picked, setPicked] = useState<string[]>(["ledgerloop/app", "ledgerloop/workers"]);

  return (
    <>
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <Link href="/proto-v3" className="v3-mark"><Mark /> ShipLock</Link>
            <div className="v3-steps" style={{ color: "var(--muted-navy)" }}>
              {STEPS.map((label, i) => (
                <div key={label} className={i === step ? "on" : i < step ? "done" : ""}>
                  <i>{i < step ? <Check size={11} /> : i + 1}</i>
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </nav>
        </div>
      </div>

      <div className="v3-narrow" style={{ padding: "52px 0 90px" }}>
        {step === 0 ? (
          <div className="v3-stack">
            <div>
              <Eyebrow>Setup · the only step there is</Eyebrow>
              <h1 className="v3-serif" style={{ fontSize: 33, margin: "12px 0 10px" }}>Connect GitHub.</h1>
              <p className="v3-sub" style={{ maxWidth: 560 }}>
                Read-only on the repositories you choose. We never ask for your database password,
                your auth keys or your payment account — your code says what it talks to, and that
                is enough to start.
              </p>
            </div>

            <div className="v3-card">
              <div className="v3-hd">
                <h2 className="v3-eyebrow">What we are asking for</h2>
                <span className="v3-tag ok">Read-only on your code</span>
              </div>
              <div className="v3-card-p">
                {[
                  { icon: LockKeyhole, name: "Repository contents", detail: "Read the code to build the map", access: "read" },
                  { icon: GitPullRequest, name: "Pull requests", detail: "Read diffs, and open fix branches for you to merge", access: "read · write" },
                  { icon: ShieldCheck, name: "Checks", detail: "Report a verdict on a pull request before you merge it", access: "write" },
                ].map((p) => {
                  const Icon = p.icon;
                  return (
                    <div className="v3-setting" key={p.name}>
                      <div className="v3-row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}>
                        <Icon size={17} style={{ marginTop: 2, color: "var(--muted)" }} />
                        <span>
                          <b style={{ fontWeight: 500, fontSize: 14.5 }}>{p.name}</b>
                          <small style={{ display: "block", color: "var(--muted)", fontSize: 13 }}>{p.detail}</small>
                        </span>
                      </div>
                      <span className="v3-mono v3-small">{p.access}</span>
                    </div>
                  );
                })}
                <p className="v3-small" style={{ marginTop: 16 }}>
                  We never push to your default branch. Uninstalling deletes the map within an hour.
                </p>
                <button
                  className="v3-btn v3-primary"
                  style={{ marginTop: 16 }}
                  disabled={installing}
                  onClick={() => {
                    setInstalling(true);
                    window.setTimeout(() => {
                      set({ connected: true });
                      setInstalling(false);
                      setStep(1);
                      toast("GitHub App installed on ledgerloop");
                    }, 900);
                  }}
                >
                  {installing ? "Authorising on github.com…" : "Install the ShipLock GitHub App"}
                </button>
              </div>
            </div>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="v3-stack">
            <div>
              <Eyebrow>Setup · repositories</Eyebrow>
              <h1 className="v3-serif" style={{ fontSize: 31, margin: "12px 0 10px" }}>Which of these are in production?</h1>
              <p className="v3-sub">
                We suggested the two that ship. Marketing sites and infrastructure repos are usually
                noise — add them later if you disagree.
              </p>
            </div>
            <div className="v3-stack" style={{ gap: 9 }}>
              {REPOS.map((r) => {
                const on = picked.includes(r.name);
                return (
                  <button
                    key={r.name}
                    className={`v3-pick${on ? " on" : ""}`}
                    aria-pressed={on}
                    onClick={() => setPicked(on ? picked.filter((x) => x !== r.name) : [...picked, r.name])}
                  >
                    <div className="v3-row" style={{ gap: 11, flexWrap: "nowrap" }}>
                      <span style={{ color: on ? "var(--bronze)" : "var(--muted-2)", display: "flex" }}>
                        {on ? <Check size={15} /> : <span style={{ width: 15 }} />}
                      </span>
                      <span>
                        <b className="v3-mono" style={{ fontSize: 13.5, fontWeight: 500 }}>{r.name}</b>
                        {r.suggested ? <span className="v3-tag" style={{ marginLeft: 8 }}>suggested</span> : null}
                        <small style={{ display: "block", color: "var(--muted)", fontSize: 12.5, marginTop: 2 }}>{r.meta}</small>
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
            <div className="v3-row">
              <button className="v3-btn v3-primary" disabled={picked.length === 0} onClick={() => { set({ repos: picked }); setStep(2); }}>
                Run the first audit
              </button>
              <span className="v3-small">{picked.length} selected · about 4 minutes · free, no card</span>
            </div>
          </div>
        ) : null}

        {step === 2 ? <RunView onDone={() => { set({ auditDone: true }); router.push("/proto-v3/app"); }} /> : null}
      </div>
    </>
  );
}

function RunView({ onDone }: { onDone: () => void }) {
  const [shown, setShown] = useState(1);
  const scrollRef = useRef<HTMLDivElement>(null);
  const done = shown >= TRACE.length;

  useEffect(() => {
    if (done) return;
    const id = window.setTimeout(() => setShown((n) => n + 1), 560);
    return () => window.clearTimeout(id);
  }, [shown, done]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [shown]);

  const seen = TRACE.slice(0, shown);
  const found = seen.filter((s) => s.found).length;
  const criticals = RISKS.filter((r) => r.severity === "critical").length;

  return (
    <div className="v3-stack">
      <div>
        <Eyebrow>First audit</Eyebrow>
        <h1 className="v3-serif" style={{ fontSize: 31, margin: "12px 0 10px" }}>
          {done ? "Audit complete." : "Reading ledgerloop/app…"}
        </h1>
        <p className="v3-sub">
          Everything the agent does is written down. You can read this back, line by line, for any
          run we ever do.
        </p>
      </div>

      <div className="v3-card">
        <div className="v3-hd">
          <div className="v3-row">
            <i className={`v3-dot ${done ? "live" : "run"}`} />
            <h2 className="v3-eyebrow">{done ? "Finished" : "Running"}</h2>
          </div>
          <span className="v3-small">{found} found so far</span>
        </div>
        <div className="v3-bar"><i style={{ width: `${(shown / TRACE.length) * 100}%` }} /></div>
        <div ref={scrollRef} className="v3-card-p" style={{ maxHeight: 340, overflowY: "auto" }}>
          <div className="v3-trace">
            {seen.map((s) => (
              <div key={s.time + s.label} className={`v3-trace-line${s.found ? " found" : ""}`}>
                <span className="v3-trace-t">{s.time}</span>
                <span>
                  <b style={{ fontWeight: 400 }}>{s.label}</b>
                  {s.note ? <small>{s.note}</small> : null}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {done ? (
        <div className="v3-card v3-card-p v3-between">
          <div>
            <b style={{ fontWeight: 500 }}>{criticals} critical, {RISKS.length} paths open.</b>
            <p className="v3-small" style={{ marginTop: 3 }}>
              The copy we tested on has been destroyed. None of your data was read.
            </p>
          </div>
          <button className="v3-btn v3-primary" onClick={onDone}>Open the results</button>
        </div>
      ) : (
        <button className="v3-btn v3-btn-sm v3-quiet" style={{ alignSelf: "flex-start" }} onClick={() => setShown(TRACE.length)}>
          Skip ahead
        </button>
      )}
    </div>
  );
}

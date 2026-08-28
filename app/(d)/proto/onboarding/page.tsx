"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { PATHS, TRACE } from "../data";
import { useProto } from "../store";
import { Mark } from "../ui";

const REPOS = [
  { name: "ledgerloop/app", meta: "TypeScript · 138k lines · pushed 2h ago", suggested: true },
  { name: "ledgerloop/marketing", meta: "TypeScript · 9k lines · pushed 5d ago", suggested: false },
  { name: "ledgerloop/workers", meta: "TypeScript · 24k lines · pushed yesterday", suggested: true },
  { name: "ledgerloop/infra", meta: "HCL · 6k lines · pushed 3w ago", suggested: false },
];

export default function Onboarding() {
  const router = useRouter();
  const { set, connected, toast } = useProto();
  const [step, setStep] = useState(connected ? 1 : 0);
  const [installing, setInstalling] = useState(false);
  const [picked, setPicked] = useState<string[]>(["ledgerloop/app", "ledgerloop/workers"]);

  return (
    <>
      <div className="pr-band">
        <div className="pr-shell">
          <nav className="pr-nav">
            <Link href="/proto" className="pr-mark"><Mark /> ShipLock</Link>
            <span className="pr-mono" style={{ fontSize: 12, color: "var(--muted-navy)" }}>
              Step {Math.min(step + 1, 3)} of 3
            </span>
          </nav>
        </div>
      </div>

      <div className="pr-narrow" style={{ padding: "56px 0 90px" }}>
        {step === 0 ? (
          <div className="pr-stack">
            <div>
              <p className="pr-eyebrow">Setup · the only step there is</p>
              <h1 className="pr-serif" style={{ fontSize: 36, margin: "12px 0 10px" }}>
                Connect GitHub.
              </h1>
              <p className="pr-sub" style={{ maxWidth: 560 }}>
                Read-only access to the repositories you choose. We never ask for your database
                password, your Clerk keys, or your Stripe account — your code tells us what it
                talks to, and that is enough to start.
              </p>
            </div>

            <div className="pr-card pr-card-p pr-stack">
              <div className="pr-between">
                <div>
                  <h3 style={{ fontSize: 15 }}>What ShipLock can do with this</h3>
                  <p className="pr-sub" style={{ fontSize: 13.5 }}>Contents: read · Pull requests: read &amp; write · Checks: write</p>
                </div>
                <span className="pr-tag pr-tag-ok">Read-only on code</span>
              </div>
              <hr className="pr-rule" />
              <ul style={{ margin: 0, paddingLeft: 18, color: "var(--muted)", fontSize: 14, lineHeight: 1.9 }}>
                <li>Read the code to build the map. We never push to your default branch.</li>
                <li>Open fix pull requests on their own branch, for you to merge or close.</li>
                <li>Post a status check on new pull requests.</li>
              </ul>
              <button
                className="pr-btn pr-btn-primary"
                disabled={installing}
                onClick={() => {
                  setInstalling(true);
                  window.setTimeout(() => {
                    set({ connected: true });
                    setInstalling(false);
                    setStep(1);
                    toast("GitHub App installed on ledgerloop");
                  }, 1100);
                }}
              >
                {installing ? "Authorising on github.com…" : "Install the ShipLock GitHub App"}
              </button>
              <p className="pr-sub" style={{ fontSize: 12.5 }}>
                Revoke any time from your GitHub settings. Uninstalling deletes the map within an hour.
              </p>
            </div>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="pr-stack">
            <div>
              <p className="pr-eyebrow">Setup · repositories</p>
              <h1 className="pr-serif" style={{ fontSize: 34, margin: "12px 0 10px" }}>
                Which repositories are production?
              </h1>
              <p className="pr-sub">
                We suggested the two that ship. Marketing sites and infra repos are usually noise —
                add them later if you disagree.
              </p>
            </div>
            <div className="pr-stack" style={{ gap: 10 }}>
              {REPOS.map((r) => {
                const on = picked.includes(r.name);
                return (
                  <button
                    key={r.name}
                    className={`pr-path${on ? " on" : ""}`}
                    onClick={() => setPicked(on ? picked.filter((x) => x !== r.name) : [...picked, r.name])}
                  >
                    <div className="pr-between">
                      <div>
                        <div className="pr-row">
                          <span style={{ color: on ? "var(--bronze)" : "var(--muted-2)" }}>{on ? "◼" : "◻"}</span>
                          <strong className="pr-mono" style={{ fontSize: 14 }}>{r.name}</strong>
                          {r.suggested ? <span className="pr-tag pr-tag-mute">suggested</span> : null}
                        </div>
                        <p className="pr-sub" style={{ fontSize: 13, marginTop: 4, paddingLeft: 24 }}>{r.meta}</p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
            <div className="pr-row">
              <button
                className="pr-btn pr-btn-primary"
                disabled={picked.length === 0}
                onClick={() => { set({ repos: picked }); setStep(2); }}
              >
                Run the first audit
              </button>
              <span className="pr-sub" style={{ fontSize: 13 }}>
                {picked.length} selected · about 4 minutes · free, no card
              </span>
            </div>
          </div>
        ) : null}

        {step === 2 ? <RunView onDone={() => { set({ auditDone: true }); router.push("/proto/app"); }} /> : null}
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
    const id = window.setTimeout(() => setShown((n) => n + 1), 620);
    return () => window.clearTimeout(id);
  }, [shown, done]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [shown]);

  const found = TRACE.slice(0, shown).filter((s) => s.found).length;

  return (
    <div className="pr-stack">
      <div>
        <p className="pr-eyebrow">First audit</p>
        <h1 className="pr-serif" style={{ fontSize: 34, margin: "12px 0 10px" }}>
          {done ? "Audit complete." : "Reading ledgerloop/app…"}
        </h1>
        <p className="pr-sub">
          Everything the agent does is written down. You can read this later, line by line, for any run.
        </p>
      </div>

      <div className="pr-card">
        <div className="pr-hd">
          <div className="pr-row">
            <span className={`pr-dot ${done ? "pr-dot-live" : "pr-dot-run"}`} />
            <h3 className="pr-eyebrow">{done ? "Finished" : "Running"}</h3>
          </div>
          <span className="pr-mono" style={{ fontSize: 12, color: "var(--muted)" }}>
            {found} finding{found === 1 ? "" : "s"} so far
          </span>
        </div>
        <div className="pr-bar"><i style={{ width: `${(shown / TRACE.length) * 100}%` }} /></div>
        <div ref={scrollRef} className="pr-card-p pr-trace" style={{ maxHeight: 360, overflowY: "auto" }}>
          {TRACE.slice(0, shown).map((s) => (
            <div key={s.t + s.body} className="pr-trace-line">
              <span className="pr-trace-t">{s.t}</span>
              <span className="pr-trace-i">{s.icon}</span>
              <span className="pr-trace-body">
                <strong className={s.found ? "pr-trace-found" : undefined}>{s.body}</strong>
                {s.note ? <div className="pr-trace-note">{s.note}</div> : null}
              </span>
            </div>
          ))}
        </div>
      </div>

      {done ? (
        <div className="pr-banner">
          <div>
            <strong>{PATHS.filter((p) => p.severity === "critical").length} critical, {PATHS.length} paths open.</strong>
            <div style={{ color: "var(--muted-navy)", fontSize: 13.5, marginTop: 4 }}>
              Two of them have a fix already validated on a disposable copy.
            </div>
          </div>
          <button className="pr-btn pr-btn-primary" onClick={onDone}>Open the report</button>
        </div>
      ) : (
        <button className="pr-btn pr-btn-ghost" onClick={() => setShown(TRACE.length)}>Skip ahead</button>
      )}
    </div>
  );
}

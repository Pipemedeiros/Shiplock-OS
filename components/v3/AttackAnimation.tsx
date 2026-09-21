"use client";

import { useEffect, useRef, useState } from "react";

/**
 * The planned proof workflow, and — just as important — where it will run.
 *
 * A security product that says "our AI attacks your app" has said something
 * alarming, and a founder is right to be alarmed. The honest version is the
 * more impressive one: the target design never touches the running
 * application. It rebuilds the table and its rules in a disposable copy with
 * NO real data, seeds it with two synthetic tenants, and runs the proof there.
 *
 * The control query is the step nobody expects and the one that makes the
 * result mean anything. A replica built wrong answers "no leak" to
 * every attack, and a broken setup would otherwise report as a clean bill of
 * health. So the run signs in as tenant A and reads A's own row first: if that
 * comes back empty, the replica is not trustworthy and we report nothing at
 * all rather than reporting good news we did not earn.
 *
 * Honesty constraint this component is under: reproducing a finding needs the
 * customer's row policies, which live in the database rather than the
 * repository. The visible label says this is in development. Overstating it
 * here would trade the one thing a security product cannot get back.
 */

interface Beat {
  label: string;
  detail: string;
  kind: "setup" | "control" | "attack" | "verdict";
}

const BEATS: Beat[] = [
  { kind: "setup", label: "Build a disposable copy", detail: "table and rules, never production rows" },
  { kind: "setup", label: "Seed two synthetic tenants", detail: "invented records only" },
  { kind: "control", label: "As tenant A, read A", detail: "control query validates the replica" },
  { kind: "attack", label: "As tenant A, try to read B", detail: "bounded proof against synthetic data" },
];

export function AttackAnimation() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);
  const reduced = useRef(false);

  useEffect(() => {
    reduced.current =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced.current) setStep(BEATS.length + 1);
  }, []);

  useEffect(() => {
    if (paused || reduced.current) return;
    const id = window.setTimeout(
      () => setStep((s) => (s >= BEATS.length + 1 ? 0 : s + 1)),
      step === 0 ? 600 : step > BEATS.length ? 3200 : 1000,
    );
    return () => window.clearTimeout(id);
  }, [step, paused]);

  const proven = step > BEATS.length;

  return (
    <div
      className="v3-attack"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      aria-label="Planned ShipLock proof workflow on a disposable copy, currently in development"
    >
      <div className="v3-attack-hd">
        <span className="v3-attack-chip">in development</span>
        <span className="v3-small">planned sandbox · never production</span>
      </div>

      <div className="v3-attack-track">
        {BEATS.map((beat, i) => (
          <div key={beat.label} className={`v3-attack-beat${step > i ? " on" : ""} ${beat.kind}`}>
            <span className="v3-attack-dot" />
            <div>
              <b>{beat.label}</b>
              <small>{beat.detail}</small>
            </div>
          </div>
        ))}
      </div>

      <div className={`v3-attack-out${proven ? " on" : ""}`} aria-live="polite">
        <p>
          <b>A cross-tenant row would make the proof reproducible.</b> The planned runner will re-run
          the approved fix against the same disposable copy.
        </p>
        <span className="v3-small">Not enabled in preview. Repository analysis does not require this step.</span>
      </div>
    </div>
  );
}

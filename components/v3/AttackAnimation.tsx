"use client";

import { useEffect, useRef, useState } from "react";

/**
 * What the agent does, and — just as important — where it does it.
 *
 * A security product that says "our AI attacks your app" has said something
 * alarming, and a founder is right to be alarmed. The honest version is the
 * more impressive one: we never touch the running application. We rebuild the
 * table and its rules in a disposable copy with NO real data, seed it with two
 * synthetic tenants, and let the agent attack that.
 *
 * The control query is the step nobody expects and the one that makes the
 * result mean anything. A replica that was built wrong answers "no leak" to
 * every attack, and a broken setup would otherwise report as a clean bill of
 * health. So the run signs in as tenant A and reads A's own row first: if that
 * comes back empty, the replica is not trustworthy and we report nothing at
 * all rather than reporting good news we did not earn.
 *
 * Honesty constraint this component is under: reproducing a finding needs the
 * customer's row policies, which live in the database rather than the
 * repository. The label says so. Overstating it here would trade the one thing
 * a security product cannot get back.
 */

interface Beat {
  label: string;
  detail: string;
  kind: "setup" | "control" | "attack" | "verdict";
}

const BEATS: Beat[] = [
  { kind: "setup", label: "Disposable copy built", detail: "your table and its rules, none of your data" },
  { kind: "setup", label: "Two synthetic tenants seeded", detail: "rows we invented, so nothing real is at risk" },
  { kind: "control", label: "Signed in as tenant A, read A", detail: "1 row — the copy is trustworthy" },
  { kind: "attack", label: "Signed in as tenant A, read B", detail: "the query a real attacker would send" },
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
      aria-label="How ShipLock proves a finding on a disposable copy instead of your live application"
    >
      <div className="v3-attack-hd">
        <span className="v3-attack-chip">sandbox</span>
        <span className="v3-small">never your production app</span>
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
          <b>1 row returned that should not exist.</b> The leak is reproduced, not inferred — and the
          fix is re-run against the same copy before it reaches you.
        </p>
        <span className="v3-small">Reproduction needs your database connected. Reading the code does not.</span>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useRef, useState } from "react";

/**
 * How the reasoning connects, animated.
 *
 * The landing page has to answer one question before anything else: what does
 * "it reads your repository" actually mean? A static screenshot cannot, and a
 * decorative loop would be worse than nothing for a buyer who writes code. So
 * this draws the real chain the product walks -- an entry point, the identity
 * it resolves, the check that is missing, the data underneath -- one step at a
 * time, in the order the audit walks it.
 *
 * It is a diagram, not an ornament: every label is something the product
 * actually produces, and the fourth step is the finding it produces on the
 * example.
 */

interface Stage {
  label: string;
  detail: string;
  kind: "entry" | "identity" | "gap" | "asset";
}

const STAGES: Stage[] = [
  { kind: "entry", label: "GET /api/invoices/:id", detail: "an entry point in your code" },
  { kind: "identity", label: "auth() resolves a user", detail: "we know who is calling" },
  { kind: "gap", label: "no workspace check", detail: "nothing narrows it to them" },
  { kind: "asset", label: "invoices", detail: "workspace-scoped billing records" },
];

export function ReasoningAnimation() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);
  const reduced = useRef(false);

  useEffect(() => {
    reduced.current =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced.current) setStep(STAGES.length);
  }, []);

  useEffect(() => {
    if (paused || reduced.current) return;
    const id = window.setTimeout(
      () => setStep((s) => (s >= STAGES.length + 1 ? 0 : s + 1)),
      step === 0 ? 700 : step > STAGES.length ? 2600 : 1100,
    );
    return () => window.clearTimeout(id);
  }, [step, paused]);

  const complete = step > STAGES.length;

  return (
    <div
      className="v3-reason"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      aria-label="How ShipLock follows a request from an entry point to the data it reaches"
    >
      <div className="v3-reason-track">
        {STAGES.map((stage, i) => {
          const on = step > i;
          return (
            <div key={stage.label} className={`v3-reason-step${on ? " on" : ""} ${stage.kind}`}>
              <span className="v3-reason-dot" />
              <div>
                <b>{stage.label}</b>
                <small>{stage.detail}</small>
              </div>
            </div>
          );
        })}
      </div>

      <div className={`v3-reason-out${complete ? " on" : ""}`} aria-live="polite">
        <span className="v3-sev critical"><i />critical</span>
        <p>Potential cross-workspace access: the query is not narrowed to the caller&rsquo;s workspace.</p>
        <span className="v3-reason-pr">Mechanical fix available for your review</span>
      </div>
    </div>
  );
}

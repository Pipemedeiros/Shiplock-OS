"use client";

import { useEffect, useRef, useState } from "react";

/**
 * The four layers one connection produces, and the finding that only exists
 * where they overlap.
 *
 * This is the argument for the whole architecture, and it is hard to make in
 * prose: none of these layers is a finding on its own. A route with no owner
 * check is ordinary. A table of invoices is ordinary. It is the JOIN that is a
 * breach, and that is why the product reads four layers out of one repository
 * instead of running four scanners that each report separately.
 *
 * Every layer here is collected from GitHub alone. Nothing on this diagram
 * requires a second connection, because the claim it is making is precisely
 * that a second connection is not required.
 */

interface Layer {
  name: string;
  reads: string;
  fact: string;
}

const LAYERS: Layer[] = [
  { name: "Entry points", reads: "route handlers", fact: "39 routes · 2 anonymous" },
  { name: "Identity", reads: "your auth library", fact: "Clerk resolves a user" },
  { name: "Data", reads: "your schema", fact: "invoices · workspace_id" },
  { name: "Dependencies", reads: "your manifest", fact: "no known advisory" },
];

export function LayersAnimation() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);
  const reduced = useRef(false);

  useEffect(() => {
    reduced.current =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced.current) setStep(LAYERS.length + 1);
  }, []);

  useEffect(() => {
    if (paused || reduced.current) return;
    const id = window.setTimeout(
      () => setStep((s) => (s >= LAYERS.length + 1 ? 0 : s + 1)),
      step === 0 ? 600 : step > LAYERS.length ? 3000 : 900,
    );
    return () => window.clearTimeout(id);
  }, [step, paused]);

  const joined = step > LAYERS.length;

  return (
    <div
      className="v3-layers"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      aria-label="The four layers ShipLock reads from one GitHub connection, and the finding where they meet"
    >
      <div className="v3-layers-grid">
        {LAYERS.map((layer, i) => (
          <div key={layer.name} className={`v3-layer${step > i ? " on" : ""}`}>
            <div className="v3-between">
              <b>{layer.name}</b>
              <span className="v3-layer-src">{layer.reads}</span>
            </div>
            <span className="v3-layer-fact">{layer.fact}</span>
          </div>
        ))}
      </div>

      <div className={`v3-layers-join${joined ? " on" : ""}`} aria-live="polite">
        <span className="v3-layers-rule" />
        <p>
          <b>Correlated.</b> An authenticated route reads <code>invoices</code> without{" "}
          <code>workspace_id</code>. None of these layers says that alone.
        </p>
      </div>
    </div>
  );
}

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
 * Every layer here is collected from GitHub alone, which is the point: the
 * audit runs and finds real paths on one connection. Connecting a service adds
 * its live configuration on top, and that is what turns an inferred finding
 * into a verified one. One connection to start, not one connection forever.
 */

interface Layer {
  name: string;
  reads: string;
  fact: string;
}

// The thesis (Felipe 2026-09-29): code, live configuration and traffic, read
// together. An illustrative example, labelled as one on the page.
const LAYERS: Layer[] = [
  { name: "Code", reads: "your repository", fact: "GET /api/invoices/export · any signed-in user" },
  { name: "Database", reads: "read only connection", fact: "invoices · no row policy" },
  { name: "Traffic", reads: "the traffic snippet", fact: "2,000 requests a minute · one account" },
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
      aria-label="An example: code, database and traffic read together, and the finding where they meet"
    >
      <p className="v3-layer-src" style={{ marginBottom: 8 }}>Example</p>
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
          <b>Together.</b> One account is exporting every row of <code>invoices</code>. No single layer says
          that alone.
        </p>
      </div>
    </div>
  );
}

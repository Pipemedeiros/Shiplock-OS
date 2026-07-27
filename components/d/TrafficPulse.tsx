"use client";

// "We are watching" — the dashboard's proof-of-work panel.
//
// The landing page has an animated traffic visual, but it's a scripted mock.
// This is its real-data counterpart: every number and every packet here comes
// from requests we actually inspected. That distinction is the entire point —
// a fabricated animation on a paying customer's dashboard would be the exact
// dishonesty this product sells against.
//
// So: when there is no data, this renders an empty state and animates nothing.
// It never invents traffic to look busy.

import { useEffect, useState } from "react";
import type { TrafficPulse as Pulse } from "@/lib/traffic/pulse";

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${Math.round(n / 1000)}k`;
  if (n >= 1_000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

/**
 * Counts up on mount. Purely presentational — the value is already real.
 *
 * State initialises to the FINAL value, so the server render and the no-JS /
 * reduced-motion case both show the true number immediately. The animation only
 * ever runs inside requestAnimationFrame, never synchronously in the effect.
 */
function Counter({ to }: { to: number }) {
  const [n, setN] = useState(to);

  useEffect(() => {
    // Small numbers don't need a ramp, and a reduced-motion user shouldn't get one.
    if (to <= 400) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const start = performance.now();
    const dur = 900;
    let raf = requestAnimationFrame(function tick(t) {
      const p = Math.min(1, (t - start) / dur);
      setN(Math.round(to * (1 - Math.pow(1 - p, 3)))); // ease-out cubic
      if (p < 1) raf = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(raf);
  }, [to]);

  return <>{fmt(n)}</>;
}

export function TrafficPulse({ pulse }: { pulse: Pulse }) {
  const [cursor, setCursor] = useState(0);

  // Cycle the live view through the real recent requests.
  useEffect(() => {
    if (pulse.recentPaths.length < 2) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setInterval(
      () => setCursor((c) => (c + 1) % pulse.recentPaths.length),
      2200
    );
    return () => clearInterval(id);
  }, [pulse.recentPaths.length]);

  if (!pulse.hasData) {
    return (
      <section className="dxd-surface" style={{ marginTop: 40 }} aria-label="Traffic watch">
        <p className="dxd-panel-label" style={{ margin: "0 0 10px" }}>
          The front door
        </p>
        <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)" }}>
          Nothing to show yet — we haven&apos;t seen a request from your app. Once the edge
          snippet is in place, every login and API call gets checked here, and this fills with
          what we actually inspected. We won&apos;t pretend otherwise until it does.
        </p>
      </section>
    );
  }

  const peak = Math.max(1, ...pulse.buckets);
  const current = pulse.recentPaths[cursor];

  return (
    <section className="dxd-surface" style={{ marginTop: 40 }} aria-label="Traffic watch">
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <p className="dxd-panel-label" style={{ margin: 0 }}>
          The front door · last {pulse.windowHours}h
        </p>
        <span className="dxd-mono dxd-livedot" style={{ fontSize: 11, color: "var(--d-verified)" }}>
          ● watching
        </span>
      </div>

      {/* Headline: the number that is large and true every day. */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
        <span className="dxd-serif" style={{ fontSize: 40, fontWeight: 700, lineHeight: 1, fontVariantNumeric: "tabular-nums" }}>
          <Counter to={pulse.watched} />
        </span>
        <span style={{ fontSize: 14, color: "var(--d-muted)" }}>
          requests checked, from {fmt(pulse.sources)} source{pulse.sources === 1 ? "" : "s"}
        </span>
      </div>

      {/* Real hourly volume. No smoothing, no invented floor. */}
      <div
        role="img"
        aria-label={`Request volume over the last ${pulse.windowHours} hours`}
        style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 54, marginTop: 18 }}
      >
        {pulse.buckets.map((v, i) => (
          <span
            key={i}
            className="dxd-pulse-bar"
            style={{
              flex: 1,
              height: `${Math.max(2, (v / peak) * 100)}%`,
              // Stagger the grow-in left→right so it reads as time passing.
              animationDelay: `${i * 26}ms`,
            }}
          />
        ))}
      </div>

      {/* The live view — real paths, cycling. */}
      {current && (
        <div
          className="dxd-mono"
          style={{
            marginTop: 16,
            fontSize: 12,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "9px 12px",
            border: "1px solid var(--d-line)",
            borderRadius: 8,
            background: "var(--d-porcelain)",
            overflow: "hidden",
          }}
        >
          <span style={{ color: current.blocked ? "var(--d-signal)" : "var(--d-verified)" }}>
            {current.blocked ? "turned away" : "passed"}
          </span>
          <span style={{ color: "var(--d-muted-light)" }}>{current.method}</span>
          <span style={{ color: "var(--d-ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {current.path}
          </span>
        </div>
      )}

      <div className="dxd-substat" style={{ marginTop: 16 }}>
        <span>
          turned away <b style={{ fontVariantNumeric: "tabular-nums" }}>{fmt(pulse.turnedAway)}</b>
        </span>
        <span>
          sources blocked now <b style={{ fontVariantNumeric: "tabular-nums" }}>{pulse.activeBlocks}</b>
        </span>
      </div>

      <p style={{ margin: "14px 0 0", fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted-light)" }}>
        Most of this is ordinary traffic, and that&apos;s the point — we check it so you know the
        quiet is real. Paths only; we never see request bodies, and sources are salted hashes,
        never raw addresses.
      </p>
    </section>
  );
}

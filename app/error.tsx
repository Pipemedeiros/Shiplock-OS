"use client";

import { useEffect } from "react";
import Link from "next/link";

/**
 * The error boundary for anything that throws while rendering a page.
 *
 * What it must never do is imply the customer's security posture changed. A
 * page that failed to render says nothing about their application, and a
 * security product that lets a rendering bug read as a security event has
 * taught its customer to distrust the real alerts.
 *
 * `digest` is Next.js's server-side error id. The message itself is withheld
 * from the browser in production on purpose, so the id is the only way a
 * customer can point us at their specific failure.
 *
 * Self-contained styles: this renders in the root layout, without the design
 * group's stylesheets, and an error page that renders wrong is worse than the
 * error.
 */
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[app] render failed:", error.digest ?? error.message);
  }, [error]);

  const INK = "#122036";
  const MUTED = "#55647a";
  const LINE = "#e3e7ed";
  const BRONZE = "#8a6b2f";

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "40px 24px",
        background: "#ffffff",
        color: INK,
        fontFamily: "var(--font-inter), ui-sans-serif, system-ui, sans-serif",
      }}
    >
      <div style={{ maxWidth: 480 }}>
        <p
          style={{
            fontFamily: "var(--font-plex-mono), ui-monospace, monospace",
            fontSize: 12,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: MUTED,
            margin: 0,
          }}
        >
          Error
        </p>

        <h1
          style={{
            fontFamily: "var(--font-fraunces), Georgia, serif",
            fontSize: 30,
            lineHeight: 1.2,
            margin: "14px 0 12px",
            fontWeight: 600,
          }}
        >
          This page failed to load.
        </h1>

        <p style={{ fontSize: 15.5, lineHeight: 1.55, color: MUTED, margin: 0 }}>
          The failure is on our side. Your audits, findings and pull requests are unaffected, and
          nothing about your application changed.
        </p>

        {error.digest ? (
          <p
            style={{
              fontFamily: "var(--font-plex-mono), ui-monospace, monospace",
              fontSize: 12.5,
              color: MUTED,
              marginTop: 16,
              padding: "8px 10px",
              border: `1px solid ${LINE}`,
              borderRadius: 5,
            }}
          >
            Reference {error.digest}
          </p>
        ) : null}

        <div style={{ display: "flex", gap: 12, marginTop: 26, flexWrap: "wrap" }}>
          <button
            onClick={reset}
            style={{
              padding: "9px 16px",
              borderRadius: 5,
              background: BRONZE,
              color: "#ffffff",
              fontSize: 14,
              border: "none",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Try again
          </button>
          <Link
            href="/dashboard"
            style={{
              display: "inline-block",
              padding: "9px 16px",
              borderRadius: 5,
              border: `1px solid ${LINE}`,
              color: INK,
              fontSize: 14,
              textDecoration: "none",
            }}
          >
            Open the dashboard
          </Link>
        </div>
      </div>
    </main>
  );
}

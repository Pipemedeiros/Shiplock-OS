import Link from "next/link";
import type { Metadata } from "next";

/**
 * The 404.
 *
 * This renders in the ROOT layout, outside the (d) route group, so it does not
 * get design-d.css, v3.css or the font variables those pages rely on. Styles
 * are therefore self-contained: an unmatched URL is exactly when a page must
 * not depend on anything, and an error page that itself renders wrong is worse
 * than the error.
 *
 * It says what happened and offers the two routes out. No apology, no
 * illustration, no invitation to contact support about a mistyped URL.
 */
export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false, follow: false },
};

const INK = "#122036";
const MUTED = "#55647a";
const LINE = "#e3e7ed";
const BRONZE = "#8a6b2f";

export default function NotFound() {
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
      <div style={{ maxWidth: 460 }}>
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
          404
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
          That page does not exist.
        </h1>

        <p style={{ fontSize: 15.5, lineHeight: 1.55, color: MUTED, margin: 0 }}>
          The address may be mistyped, or the page may have been removed. Nothing is wrong with your
          account or your audits.
        </p>

        <div style={{ display: "flex", gap: 12, marginTop: 26, flexWrap: "wrap" }}>
          <Link
            href="/"
            style={{
              display: "inline-block",
              padding: "9px 16px",
              borderRadius: 5,
              background: BRONZE,
              color: "#ffffff",
              fontSize: 14,
              textDecoration: "none",
            }}
          >
            Go to the home page
          </Link>
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

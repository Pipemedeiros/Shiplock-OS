"use client";

/**
 * The last boundary: an error thrown by the root layout itself.
 *
 * This replaces the entire document, so it has to supply its own html and body.
 * Nothing from the root layout is available here, fonts included, which is why
 * everything below is a system stack and a literal colour. If this page needs
 * something to render, it will not render.
 *
 * It is deliberately plainer than app/error.tsx. Reaching here means the shell
 * failed, so offering a "try again" that re-mounts the same broken tree would
 * mostly loop; a reload is the honest action.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "40px 24px",
          background: "#ffffff",
          color: "#122036",
          fontFamily: "ui-sans-serif, system-ui, -apple-system, sans-serif",
        }}
      >
        <div style={{ maxWidth: 460 }}>
          <p
            style={{
              fontFamily: "ui-monospace, monospace",
              fontSize: 12,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "#55647a",
              margin: 0,
            }}
          >
            Error
          </p>
          <h1 style={{ fontSize: 27, lineHeight: 1.2, margin: "14px 0 12px", fontWeight: 600 }}>
            ShipLock failed to start.
          </h1>
          <p style={{ fontSize: 15.5, lineHeight: 1.55, color: "#55647a", margin: 0 }}>
            The failure is on our side. Your audits and findings are stored and unaffected.
          </p>
          {error.digest ? (
            <p
              style={{
                fontFamily: "ui-monospace, monospace",
                fontSize: 12.5,
                color: "#55647a",
                marginTop: 16,
              }}
            >
              Reference {error.digest}
            </p>
          ) : null}
          <button
            onClick={reset}
            style={{
              marginTop: 26,
              padding: "9px 16px",
              borderRadius: 5,
              background: "#8a6b2f",
              color: "#ffffff",
              fontSize: 14,
              border: "none",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Reload
          </button>
        </div>
      </body>
    </html>
  );
}

// Presentational, server-safe (no hooks). Renders the copy-paste install
// snippet for the customer's app. Snippet text (with their site token) is built
// server-side via lib/traffic/snippet.ts and passed in — the token is a live
// per-site credential, same sensitivity as the deploy-webhook URL, so it's only
// ever rendered for a paid, authenticated owner viewing their own dashboard.
// Alternate frameworks live in native <details> (no client JS).

const preStyle = {
  margin: 0,
  fontSize: 10.5,
  lineHeight: 1.5,
  maxHeight: 220,
  overflow: "auto" as const,
  background: "var(--d-porcelain)",
  border: "1px solid var(--d-line)",
  borderRadius: 8,
  padding: "12px 14px",
  userSelect: "all" as const,
  whiteSpace: "pre" as const,
};

export function EdgeSnippet({
  snippet,
  webSnippet,
  expressSnippet,
  installed,
}: {
  snippet: string;
  webSnippet?: string;
  expressSnippet?: string;
  installed: boolean;
}) {
  return (
    <div className="dxd-surface">
      <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>
        {installed ? "Protection installed" : "Install protection"}
      </h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        Save this as <code className="dxd-mono">middleware.ts</code> in your project root and
        deploy. It watches your login and API routes and blocks malicious sources — and it
        fails open: if ShipLock is ever unreachable, your app keeps serving normally, with no
        added latency. Safe to remove anytime. The key inside is unique to your account —
        treat it like a password.
      </p>
      <pre className="dxd-mono" style={preStyle}>
        {snippet}
      </pre>

      {(webSnippet || expressSnippet) && (
        <details style={{ marginTop: 12 }}>
          <summary style={{ cursor: "pointer", fontSize: 12.5, color: "var(--d-bronze)" }}>
            Not using Next.js? Other frameworks
          </summary>
          {webSnippet && (
            <div style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 6px", fontSize: 12, color: "var(--d-muted)" }}>
                Hono · Cloudflare Workers · Deno · Bun · SvelteKit · Remix — call{" "}
                <code className="dxd-mono">shiplockGuard(request)</code> at the top of your handler.
              </p>
              <pre className="dxd-mono" style={preStyle}>
                {webSnippet}
              </pre>
            </div>
          )}
          {expressSnippet && (
            <div style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 6px", fontSize: 12, color: "var(--d-muted)" }}>
                Express · Connect — <code className="dxd-mono">app.use(shiplock)</code> before your routes.
              </p>
              <pre className="dxd-mono" style={preStyle}>
                {expressSnippet}
              </pre>
            </div>
          )}
          <p style={{ margin: "10px 0 0", fontSize: 11.5, color: "var(--d-muted)" }}>
            Pure static single-page apps with no server or edge layer can&apos;t run this — it
            needs somewhere server-side to sit. Add it wherever your app handles requests.
          </p>
        </details>
      )}
    </div>
  );
}

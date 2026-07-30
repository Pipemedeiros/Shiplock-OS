// Presentational, server-safe (no hooks). Renders the OPTIONAL edge snippet.
//
// Framing matters here and it changed once E5-E7 shipped. Detection of
// credential stuffing, brute force and account takeover now runs from Supabase's
// own auth log, which needs nothing installed — so this snippet is no longer how
// protection begins, it is an upgrade from "we tell you" to "we stop it in the
// request". The connection budget is two, GitHub and Supabase, and a panel
// headed "Install protection" quietly implies a third step is required for the
// product to work. It is not, and the copy must not suggest otherwise. Snippet text (with their site token) is built
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
        {installed ? "Blocking at the edge — installed" : "Optional: block attacks in the request"}
      </h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        You don&apos;t need this. We already watch your sign-in activity through Supabase, so
        credential stuffing, password attacks and account takeovers get detected and reported
        without you installing anything. This snippet changes what happens next: instead of
        telling you afterwards, it turns malicious requests away as they arrive. Save it as{" "}
        <code className="dxd-mono">middleware.ts</code> in your project root and deploy. It fails
        open — if ShipLock is ever unreachable your app keeps serving normally, with no added
        latency — and it is safe to remove at any time. The key inside is unique to your account,
        so treat it like a password.
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

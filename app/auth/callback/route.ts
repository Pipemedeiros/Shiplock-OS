import { NextRequest, NextResponse } from "next/server";
import { getSupabaseServer } from "@/lib/supabaseServer";

// OAuth (and email-link) callback. Supabase Auth handles the state
// parameter itself as part of the PKCE flow — this route only exchanges
// the authorization code for a session; it never sees or validates state
// directly, that happens inside exchangeCodeForSession() against the
// code_verifier stored in the PKCE cookie set when the flow started.
//
// TWO WAYS IN, ONE EXCHANGE. The provider can be opened either as a full-page
// redirect or in a small window, the way Google's own sign-in behaves
// everywhere else. Which one is decided by a cookie the client sets before it
// opens the window, NOT by a query parameter on the redirect URL:
// `redirect_to` is matched against the allow-list configured in the Supabase
// dashboard, and adding parameters to it is how a working sign-in starts
// failing for a reason nobody can see from the code. The cookie leaves the
// redirect URL untouched.

/** Set by the client immediately before it opens the sign-in window. */
const POPUP_COOKIE = "sl_oauth_popup";

/**
 * `next` arrives in the query string, so it is attacker-supplied.
 *
 * Only a path on this site is allowed. Rejected: an absolute URL
 * (`https://evil.example`), a protocol-relative one (`//evil.example`), the
 * backslash form some browsers normalise to it (`/\evil.example`), and any
 * scheme at all (`javascript:...`), which would otherwise run when the
 * completion page navigates itself.
 */
export function safeNext(raw: string | null): string {
  const fallback = "/onboarding";
  if (!raw || raw[0] !== "/") return fallback;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return fallback;
  return raw;
}

/**
 * JSON safe to embed inside a <script> block.
 *
 * JSON.stringify does not escape `<`, so a value containing `</script>` closes
 * the block early and everything after it is markup the browser will run. The
 * line separators are escaped because they are literal newlines to a JavaScript
 * parser and would break the statement.
 */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * The page the small window shows for the fraction of a second it still exists.
 *
 * It hands the result to the page that opened it and closes. The session itself
 * is already set: exchangeCodeForSession wrote the auth cookies on this origin,
 * and the opener shares them, so the message carries an outcome rather than
 * anything sensitive.
 *
 * targetOrigin is this exact origin, never "*" — a wildcard would broadcast the
 * message to whatever document happens to be listening.
 */
function popupCompletionPage(origin: string, nonce: string, ok: boolean, next: string): string {
  const payload = jsonForScript({ source: "shiplock-auth", ok, next });
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${ok ? "Signed in" : "Sign-in failed"}</title>
<style nonce="${nonce}">
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
         color:#1B2233; background:#F5F6FA; }
  @media (prefers-color-scheme: dark) { body { color:#DFE3ED; background:#0C111C; } }
  p { margin:0; }
</style>
</head>
<body>
<p>${ok ? "Signed in. You can close this window." : "Sign-in did not go through. You can close this window."}</p>
<script nonce="${nonce}">
(function () {
  var payload = ${payload};
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(payload, ${JSON.stringify(origin)});
      window.close();
      return;
    }
  } catch (e) {
    // Opener gone or unreachable: fall through and navigate this window
    // instead, so the person is never stranded on a blank page.
  }
  window.location.replace(payload.ok ? payload.next : "/auth?error=oauth_failed");
})();
</script>
</body>
</html>`;
}

export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const code = searchParams.get("code");
  const next = safeNext(searchParams.get("next"));
  const inPopup = req.cookies.get(POPUP_COOKIE)?.value === "1";

  let ok = false;
  if (code) {
    const supabase = await getSupabaseServer();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) {
      console.error("[auth/callback] exchangeCodeForSession error:", error.message);
    } else {
      ok = true;
    }
  }

  const response = inPopup
    ? new NextResponse(
        popupCompletionPage(origin, req.headers.get("x-nonce") ?? "", ok, next),
        { headers: { "content-type": "text/html; charset=utf-8" } },
      )
    : NextResponse.redirect(`${origin}${ok ? next : "/auth?error=oauth_failed"}`);

  // Whichever way it went, the flag has served its purpose. Leaving it set
  // would make the NEXT sign-in render a completion page inside the main tab.
  if (inPopup) response.cookies.set(POPUP_COOKIE, "", { path: "/", maxAge: 0 });

  return response;
}

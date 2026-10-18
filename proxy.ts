import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextFetchEvent, type NextRequest } from "next/server";
import { observeSelf } from "@/lib/traffic/selfObserve";

const isDev = process.env.NODE_ENV === "development";

// Nonce-based CSP, generated fresh per request, per Next.js's own guidance
// for the App Router (https://nextjs.org/docs/app/guides/content-security-policy).
// This has to live here rather than next.config.ts's static headers() because
// the nonce must be unique per request — a static header can't do that.
// Setting the header on BOTH the outgoing request (so Next.js's own RSC/
// hydration scripts pick up the nonce when rendering) and the response
// (so the browser enforces it) is required — Next.js reads the nonce from
// the *request's* CSP header to know what to stamp its own inline scripts
// with.
//
// 'strict-dynamic' lets scripts loaded by an already-nonced script run too
// (needed for Next.js's code-split chunks) without listing every host or
// falling back to 'unsafe-inline' — which would silently defeat the CSP's
// actual purpose of blocking injected/attacker-controlled inline scripts.
function supabaseOrigins(url: string | undefined): string {
  try {
    const origin = new URL(url ?? "").origin;
    if (!/^https?:\/\//.test(origin)) return "";
    return `${origin} ${origin.replace(/^https:/, "wss:").replace(/^http:/, "ws:")} `;
  } catch {
    return "";
  }
}

function buildCsp(nonce: string): string {
  // Google One Tap: our nonced bundle inserts Google's client script, which
  // 'strict-dynamic' trusts; the host is listed for browsers without it.
  const google = "https://accounts.google.com";
  const scriptSrc = isDev
    ? `'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval' ${google}/gsi/client`
    : `'self' 'nonce-${nonce}' 'strict-dynamic' ${google}/gsi/client`;
  // PostHog: the JS bundle ships from our own origin (npm package), but it
  // phones home to us.i.posthog.com (events/remote config) and
  // us-assets.i.posthog.com (surveys/toolbar assets) — both connect-src only.
  // Only our own Supabase project (REST and realtime), never *.supabase.co. A
  // missing or malformed URL names no Supabase origin rather than crashing.
  const supabase = supabaseOrigins(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const connectSrc = isDev
    ? `'self' ws: https://api.stripe.com ${supabase}https://us.i.posthog.com https://us-assets.i.posthog.com ${google}`
    : `'self' https://api.stripe.com ${supabase}https://us.i.posthog.com https://us-assets.i.posthog.com ${google}`;

  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    `style-src 'self' 'unsafe-inline' ${google}/gsi/style`,
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src ${connectSrc}`,
    `frame-src https://js.stripe.com https://checkout.stripe.com ${google}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/** How long the auth refresh may take before we give up and serve the page. */
const AUTH_REFRESH_TIMEOUT_MS = 3_000;

/**
 * Whether this request carries a Supabase session at all.
 *
 * @supabase/ssr stores the session in `sb-<project-ref>-auth-token`, split into
 * `.0`, `.1` chunks when it is long. No such cookie means nobody is signed in,
 * and there is no token to refresh.
 */
function hasSessionCookie(request: NextRequest): boolean {
  return request.cookies.getAll().some((c) => /^sb-.+-auth-token(\.\d+)?$/.test(c.name));
}

// Refreshes the Supabase session cookie so it doesn't expire between page
// loads, which SSR auth with @supabase/ssr requires. Per Supabase's own Next.js
// guidance: do not add logic between createServerClient and getClaims(), and
// always return the `response` object created here (not a new NextResponse) so
// refreshed cookies aren't dropped.
//
// Two things bound it, and production needed both. The auth call is a network
// request to Supabase, it ran on EVERY request including anonymous hits on the
// landing page, and it had no timeout. When that call hung, Vercel killed the
// middleware at 25 seconds and returned 504 for the whole page: 41 of them in
// 48 hours, across every route including static ones like /terms, because
// middleware sits in front of all of them. The landing page had the most,
// since it takes the most anonymous traffic and every one of those was asking
// the auth server to refresh a session that did not exist.
export async function proxy(request: NextRequest, event?: NextFetchEvent) {
  // ShipLock watching its own traffic (selfObserve.ts): after the response.
  event?.waitUntil(observeSelf(request));
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildCsp(nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  let response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = NextResponse.next({ request: { headers: requestHeaders } });
          response.headers.set("Content-Security-Policy", csp);
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // 1. Nobody signed in, nothing to refresh. An anonymous visitor never waits
  //    on a network call, which is most of the traffic on the public pages.
  // 2. A signed-in request is bounded. If the auth server is slow we serve the
  //    page with the session cookie the browser already has, rather than
  //    hanging until the platform kills us. A missed refresh costs a token that
  //    expires slightly sooner; a hang costs the entire site.
  if (hasSessionCookie(request)) {
    try {
      await Promise.race([
        // getClaims refreshes a token about to expire, like getUser, and with
        // asymmetric signing keys verifies locally instead of calling the
        // auth server. Never an authority here (below), so nothing is trusted
        // from it.
        supabase.auth.getClaims(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("auth refresh timed out")), AUTH_REFRESH_TIMEOUT_MS),
        ),
      ]);
    } catch (err) {
      // Never fatal. The page's own server-side getUser is the authority on
      // whether this caller is signed in; this is only the refresh.
      console.warn(
        "[proxy] session refresh skipped:",
        err instanceof Error ? err.message : err,
      );
    }
  }

  // setAll may have replaced `response` above — make sure the CSP header
  // survived onto whichever object is actually returned.
  response.headers.set("Content-Security-Policy", csp);

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};

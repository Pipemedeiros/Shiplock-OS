import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

const isDev = process.env.NODE_ENV !== "production";

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
function buildCsp(nonce: string): string {
  const scriptSrc = isDev
    ? `'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`
    : `'self' 'nonce-${nonce}' 'strict-dynamic'`;
  const connectSrc = isDev
    ? "'self' ws: https://api.stripe.com https://*.supabase.co"
    : "'self' https://api.stripe.com https://*.supabase.co";

  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src ${connectSrc}`,
    "frame-src https://js.stripe.com https://checkout.stripe.com",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// Refreshes the Supabase session cookie on every request so it doesn't
// expire between page loads — required for SSR auth with @supabase/ssr.
// Per Supabase's own Next.js guidance: do not add logic between
// createServerClient and getUser(), and always return the `response`
// object created here (not a new NextResponse) so refreshed cookies aren't
// dropped.
export async function middleware(request: NextRequest) {
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

  // Touches auth server to refresh the token if needed — do not remove.
  await supabase.auth.getUser();

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

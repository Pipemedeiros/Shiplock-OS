import { NextResponse } from "next/server";

/**
 * Same-origin guard for cookie-authenticated mutations. A session cookie
 * proves who, not that ShipLock's own page asked; browsers send `Origin` on
 * every POST/DELETE, so require it to be ours. Allowed: the request URL's
 * origin, or the configured public app origin (NEXT_PUBLIC_APP_URL) for when
 * the handler sees an internal URL. Forwarding headers are never trusted here.
 * Routes that authenticate with a Bearer header are not cookie-driven and do
 * not need this.
 */
export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return false;
  const allowed = new Set([new URL(request.url).origin]);
  try { if (process.env.NEXT_PUBLIC_APP_URL) allowed.add(new URL(process.env.NEXT_PUBLIC_APP_URL).origin); } catch { /* unset or malformed */ }
  return allowed.has(origin);
}

/** A 403 for a cross-site request, or null when the request is same-origin. */
export function crossSiteRefusal(request: Request): NextResponse | null {
  return isSameOrigin(request) ? null : NextResponse.json({ error: "A same-origin request is required." }, { status: 403 });
}

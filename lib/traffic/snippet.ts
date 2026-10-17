import { probeSnippetSource } from "./probe";

// Generates the fail-open middleware the customer pastes into their Next.js
// app. Delivered as text on the dashboard today (copy-paste); PR-delivered
// once the GitHub App exists. This is NOT ShipLock's own middleware: it runs
// in the customer's compute and must fail open: our being down can never take
// their app down or add latency to their hot path.
//
// Design (as sketched with the owner): hot path is one SHA-256 + one in-memory
// Set.has(); the mirror POST and blocklist refresh run in ev.waitUntil() after
// the response ships, each with a 2s abort ceiling and every error swallowed.
// source_id is salted with the site token (stable per-site, so a block stays
// valid across its whole TTL, and unlinkable across different sites).
export function buildSnippet(ingestToken: string, origin: string): string {
  return `// ShipLock edge traffic protection: fail-open. Safe to remove anytime.
// Our being unreachable never blocks or slows your app.
// Next.js 16: save this as proxy.ts and rename the function middleware to proxy.
// It runs before your routes, so it reports requests, not how your app answered.
import { NextRequest, NextResponse, NextFetchEvent } from "next/server";

const SHIPLOCK_ORIGIN = ${JSON.stringify(origin)};
const SHIPLOCK_SITE = ${JSON.stringify(ingestToken)}; // your site key: treat like a password

let blocklist = new Set<string>();
let fetchedAt = 0;
const REFRESH_MS = 30_000;

// Attack probes, classified here in your server. Only the category (for
// example "sqli") is sent to ShipLock, never the query string.
${probeSnippetSource()}

export async function middleware(req: NextRequest, ev: NextFetchEvent) {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",").pop()?.trim() ||
    req.headers.get("x-real-ip") ||
    "anonymous";
  const id = await sourceId(ip);

  // 1) ENFORCE: synchronous in-memory lookup. Empty set (cold start) = allow.
  if (blocklist.has(id)) {
    return new NextResponse("Too many requests", { status: 429 });
  }

  // 2) MIRROR: after the response ships; never blocks or slows the request.
  //    Include a salted hash of the session (never the raw token) so ShipLock
  //    can spot one session used from many places at once (session theft).
  const sess = await sessionId(req);
  ev.waitUntil(sendEvent(id, sess, req));

  // 3) REFRESH the blocklist opportunistically, also off the response path.
  if (Date.now() - fetchedAt > REFRESH_MS) ev.waitUntil(refreshBlocklist());

  return NextResponse.next();
}

async function sendEvent(id: string, sess: string | null, req: NextRequest) {
  try {
    await fetch(SHIPLOCK_ORIGIN + "/api/traffic/ingest", {
      method: "POST",
      headers: { "content-type": "application/json", "x-site": SHIPLOCK_SITE },
      body: JSON.stringify({
        source_id: id,
        session_id: sess, // hashed session, or null when signed-out
        path: new URL(req.url).pathname, // pathname only, never the query string
        probe: probeKind(new URL(req.url).pathname + new URL(req.url).search), // a category or null, never the query
        method: req.method,
        ua: req.headers.get("user-agent") || null,
        t: Date.now(),
      }),
      signal: AbortSignal.timeout(2000),
    });
  } catch {
    /* fire-and-forget: drop, never throw */
  }
}

// Hash of the Supabase auth cookie, if present: identifies "the same session"
// across requests without ever sending us the raw token. Returns null when the
// request carries no auth cookie (anonymous).
async function sessionId(req: NextRequest): Promise<string | null> {
  const cookie = req.cookies.getAll().find((c) => /^sb-.*-auth-token(\\.\\d+)?$/.test(c.name));
  if (!cookie?.value) return null;
  const bytes = new TextEncoder().encode(cookie.value + ":s:" + SHIPLOCK_SITE);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).slice(0, 22);
}

async function refreshBlocklist() {
  try {
    const res = await fetch(SHIPLOCK_ORIGIN + "/api/traffic/blocklist?site=" + SHIPLOCK_SITE, {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return; // keep the current list on any error
    const body = (await res.json()) as { hashes: string[] };
    blocklist = new Set(body.hashes);
    fetchedAt = Date.now();
  } catch {
    /* keep serving the stale list: never throw */
  }
}

async function sourceId(ip: string): Promise<string> {
  const bytes = new TextEncoder().encode(ip + ":" + SHIPLOCK_SITE);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).slice(0, 22);
}

// Only watch auth + API routes: where attacks land, and keeps volume bounded.
export const config = {
  matcher: ["/api/:path*", "/login", "/signin", "/sign-in", "/register", "/auth/:path*"],
};
`;
}

// Web-standard (Request/Response + Web Crypto) variant: for any server/edge
// framework that isn't Next.js: Hono, Cloudflare Workers, Deno, Bun, SvelteKit
// hooks, Remix/React Router loaders. Same fail-open guarantees. Exposes a
// `shiplockGuard(request)` you call at the top of your handler.
export function buildWebSnippet(ingestToken: string, origin: string): string {
  return `// ShipLock edge traffic protection (Web-standard): fail-open. Safe to remove.
// Runs server-side; the key stays out of the browser. Our being unreachable
// never blocks or slows your app.
const SHIPLOCK_ORIGIN = ${JSON.stringify(origin)};
const SHIPLOCK_SITE = ${JSON.stringify(ingestToken)}; // your site key: treat like a password

let blocklist = new Set();
let fetchedAt = 0;
const REFRESH_MS = 30_000;

// Attack probes, classified here in your server. Only the category (for
// example "sqli") is sent to ShipLock, never the query string.
${probeSnippetSource()}

// Returns a 429 Response if the caller is blocked, otherwise null (allow).
// Usage (Hono):  app.use(async (c, next) => { const b = await shiplockGuard(c.req.raw); if (b) return b; await next(); })
// Usage (Workers): const b = await shiplockGuard(request); if (b) return b;
export async function shiplockGuard(request) {
  const url = new URL(request.url);
  if (!/^\\/(api|login|signin|sign-in|register|auth)(\\/|$)/.test(url.pathname)) return null;

  const ip =
    request.headers.get("x-forwarded-for")?.split(",").pop()?.trim() ||
    request.headers.get("x-real-ip") ||
    "anonymous";
  const id = await hash(ip + ":" + SHIPLOCK_SITE);

  if (blocklist.has(id)) return new Response("Too many requests", { status: 429 });

  const sess = await sessionHash(request);
  // fire-and-forget: do not await; never let this block the response
  void mirror(id, sess, url.pathname, probeKind(url.pathname + url.search), request, null);
  if (Date.now() - fetchedAt > REFRESH_MS) void refresh();
  return null;
}

// Preferred: wrap your fetch handler so ShipLock also learns how your app
// answered (the status code only, never the body). Same checks as the guard.
// Usage (Workers, Bun, Deno): export default { fetch: withShiplock(handler) }
// Usage (Hono):               export default { fetch: withShiplock(app.fetch) }
export function withShiplock(handler) {
  return async (request, ...rest) => {
    const url = new URL(request.url);
    if (!/^\\/(api|login|signin|sign-in|register|auth)(\\/|$)/.test(url.pathname)) return handler(request, ...rest);
    const ip =
      request.headers.get("x-forwarded-for")?.split(",").pop()?.trim() ||
      request.headers.get("x-real-ip") ||
      "anonymous";
    const id = await hash(ip + ":" + SHIPLOCK_SITE);
    if (blocklist.has(id)) return new Response("Too many requests", { status: 429 });
    const sess = await sessionHash(request);
    const probe = probeKind(url.pathname + url.search);
    // Workers pass a context whose waitUntil keeps the report alive after the response.
    const ctx = rest.find((x) => x && typeof x.waitUntil === "function");
    const later = (p) => (ctx ? ctx.waitUntil(p) : void p);
    if (Date.now() - fetchedAt > REFRESH_MS) later(refresh());
    let response;
    try {
      response = await handler(request, ...rest);
    } catch (err) {
      later(mirror(id, sess, url.pathname, probe, request, 500));
      throw err;
    }
    later(mirror(id, sess, url.pathname, probe, request, response.status));
    return response;
  };
}

async function mirror(id, sess, path, probe, request, status) {
  try {
    await fetch(SHIPLOCK_ORIGIN + "/api/traffic/ingest", {
      method: "POST",
      headers: { "content-type": "application/json", "x-site": SHIPLOCK_SITE },
      body: JSON.stringify({
        source_id: id, session_id: sess, path, probe, status,
        method: request.method, ua: request.headers.get("user-agent") || null, t: Date.now(),
      }),
      signal: AbortSignal.timeout(2000),
    });
  } catch { /* drop */ }
}

async function refresh() {
  try {
    const res = await fetch(SHIPLOCK_ORIGIN + "/api/traffic/blocklist?site=" + SHIPLOCK_SITE, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return;
    blocklist = new Set((await res.json()).hashes);
    fetchedAt = Date.now();
  } catch { /* keep stale list */ }
}

async function sessionHash(request) {
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/sb-[^=;]*-auth-token(?:\\.\\d+)?=([^;]+)/);
  if (!m) return null;
  return hash(m[1] + ":s:" + SHIPLOCK_SITE);
}

async function hash(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).slice(0, 22);
}
`;
}

// Express / Connect variant: for traditional Node servers (Express, Fastify
// via middie, etc.). Same fail-open guarantees; uses node:crypto.
export function buildExpressSnippet(ingestToken: string, origin: string): string {
  return `// ShipLock edge traffic protection (Express): fail-open. Safe to remove.
// app.use(shiplock) : mount before your routes.
const crypto = require("crypto");

const SHIPLOCK_ORIGIN = ${JSON.stringify(origin)};
const SHIPLOCK_SITE = ${JSON.stringify(ingestToken)}; // your site key: treat like a password

let blocklist = new Set();
let fetchedAt = 0;
const REFRESH_MS = 30_000;
const hash = (s) => crypto.createHash("sha256").update(s).digest("base64").replace(/=+$/, "").slice(0, 22);

// Attack probes, classified here in your server. Only the category (for
// example "sqli") is sent to ShipLock, never the query string.
${probeSnippetSource()}

function shiplock(req, res, next) {
  if (!/^\\/(api|login|signin|sign-in|register|auth)(\\/|$)/.test(req.path)) return next();

  const ip = (req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress || "anonymous";
  const id = hash(ip + ":" + SHIPLOCK_SITE);
  if (blocklist.has(id)) return res.status(429).send("Too many requests");

  const m = (req.headers.cookie || "").match(/sb-[^=;]*-auth-token(?:\\.\\d+)?=([^;]+)/);
  const sess = m ? hash(m[1] + ":s:" + SHIPLOCK_SITE) : null;

  const event = { source_id: id, session_id: sess, path: req.path, probe: probeKind(req.originalUrl || req.url), method: req.method, ua: req.headers["user-agent"] || null, t: Date.now() };
  // After your app answered: its status code only, never a body or a header.
  // An aborted request that never sent headers reports none. Fire-and-forget.
  res.once("close", () => {
    fetch(SHIPLOCK_ORIGIN + "/api/traffic/ingest", {
      method: "POST",
      headers: { "content-type": "application/json", "x-site": SHIPLOCK_SITE },
      body: JSON.stringify({ ...event, status: res.headersSent ? res.statusCode : null }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => {});
  });

  if (Date.now() - fetchedAt > REFRESH_MS) {
    fetch(SHIPLOCK_ORIGIN + "/api/traffic/blocklist?site=" + SHIPLOCK_SITE, { signal: AbortSignal.timeout(2000) })
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => { if (b) { blocklist = new Set(b.hashes); fetchedAt = Date.now(); } })
      .catch(() => {});
  }
  next();
}

module.exports = { shiplock };
`;
}

import { ingestTrafficEvent } from "@/lib/traffic/ingest";
import { resolveTrafficSiteById, type TrafficIdentity } from "@/lib/traffic/sites";

/**
 * ShipLock watching its own traffic (Felipe 2026-10-01, dogfooding). proxy.ts
 * calls this in event.waitUntil, after the response, so it never blocks or
 * slows a page. It records what the customer snippet records (path without the
 * query, method, user agent, a salted visitor hash) into the traffic site for
 * shiplock.dev, in-process (no extra HTTP hop). The site id is not a secret: it
 * only names where ShipLock's own traffic is filed, and the site must exist,
 * be unrevoked, entitled and bound to a selected repository.
 */
const SELF_TRAFFIC_SITE = process.env.SHIPLOCK_SELF_TRAFFIC_SITE ?? "f5b95d52-77fa-4e37-9f65-be133d889420";

const SKIP = /^\/(?:_next\/|api\/traffic\/|api\/health(?:\/|$))|\.(?:txt|xml|ico|png|svg|jpe?g|webp|gif|css|js|map|woff2?)$/i;
const CACHE_MS = 5 * 60 * 1000;
let cached: { siteId: string; identity: TrafficIdentity | null; at: number } | null = null;

/** Clears the cached self-observation site (tests). */
export function resetSelfSiteCache(): void { cached = null; }

/** Whether ShipLock records its own request: never prefetches or static assets. */
export function shouldObserve(request: Request): boolean {
  if (request.headers.get("next-router-prefetch") || request.headers.get("purpose") === "prefetch") return false;
  return !SKIP.test(new URL(request.url).pathname);
}

/** Same construction as the customer snippet: a salted hash, never the address. */
export async function visitorId(ip: string, salt: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${ip}:${salt}`));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).slice(0, 22);
}

/** Records ShipLock's own traffic through the same path as a customer's
 * snippet. */
export async function observeSelf(request: Request, siteId: string | undefined = SELF_TRAFFIC_SITE): Promise<void> {
  try {
    if (!siteId || !shouldObserve(request)) return;
    if (!cached || cached.siteId !== siteId || Date.now() - cached.at > CACHE_MS) {
      cached = { siteId, identity: await resolveTrafficSiteById(siteId), at: Date.now() };
    }
    const identity = cached.identity;
    if (!identity) return;
    const ip = request.headers.get("x-forwarded-for")?.split(",").pop()?.trim() || request.headers.get("x-real-ip") || "anonymous";
    await ingestTrafficEvent({
      userId: identity.userId, email: identity.email, siteId: identity.siteId, repositoryId: identity.repositoryId,
      event: { source_id: await visitorId(ip, siteId), path: new URL(request.url).pathname, method: request.method,
        ua: request.headers.get("user-agent"), session_id: null, t: Date.now() },
    });
  } catch {
    // Observation is best effort: it must never break or slow ShipLock itself.
  }
}

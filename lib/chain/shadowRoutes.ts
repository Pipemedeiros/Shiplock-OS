import { routeMatcher } from "@/lib/graph/clientReach";
import { API_PATH } from "@/lib/security/shippedCalls";
import { MAX_STORED } from "@/lib/routeMap";
import type { LiveReach } from "./liveReach";

/**
 * Shadow routes (G3, the outside view): backend addresses the founder's live
 * site requests on its own origin that the bound repository declares no route
 * for. A rewrite, another service, a platform function or an older deploy can
 * serve them; whichever it is, ShipLock has read no code for them, so they are
 * surface that was not checked. Never an issue on their own, never a status.
 *
 * Only requests count (lib/security/shippedCalls.ts requestedPaths): a path an
 * SDK builds on its own host is not the app's. A list is only as complete as
 * both reads: unknown when either side is missing or may be truncated, and
 * partial when scripts went unread.
 */
export type ShadowRoutes =
  | { state: "read"; paths: string[]; partial: boolean }
  | { state: "unknown"; why: string };

const TRPC = /^\/(?:api\/)?trpc(?:\/|$)/;

export function shadowRoutes(live: LiveReach | null, routes: readonly { path: string }[] | null): ShadowRoutes {
  if (!live) return { state: "unknown", why: "No app address is bound to this repository." };
  if (!live.requests) return { state: "unknown", why: "The live site has not been read since requests were recorded." };
  if (!routes) return { state: "unknown", why: "No audit of this repository stored its routes." };
  if (routes.length >= MAX_STORED) return { state: "unknown", why: "The repository has more routes than an audit stores." };
  const declared = routes.flatMap((r) => {
    if (r.path.startsWith("action:")) return [];
    if (r.path.startsWith("trpc:")) return [(p: string) => TRPC.test(p)];
    const matches = routeMatcher(r.path);
    const bare = r.path.startsWith("/") ? r.path : r.path.slice(r.path.indexOf(":/") + 1);
    // A request cut at a template hole ends in "/": any route under it serves it.
    return [(p: string) => (matches?.(p) ?? false) || (p.endsWith("/") && bare.startsWith(p))];
  });
  const paths = live.requests.filter((p) => API_PATH.test(p) && !declared.some((d) => d(p))).sort();
  const { scriptsSeen, scriptsRead } = live.read;
  return { state: "read", paths, partial: scriptsSeen === null || scriptsRead === null || scriptsRead < scriptsSeen };
}

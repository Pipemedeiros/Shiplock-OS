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
 *
 * Deploy drift: a shadow route an earlier audit of the same repository
 * declared is listed under removed. The code dropped it and the live site
 * still requests it, so the deployed build is older than the repository (a
 * fix merged but not deployed, a failed build). The repository alone would
 * call that route gone.
 */
export type ShadowRoutes =
  | { state: "read"; paths: string[]; partial: boolean; removed: string[]; codeUnread: boolean }
  | { state: "unknown"; why: string };

const TRPC = /^\/(?:api\/)?trpc(?:\/|$)/;

type Routes = readonly { path: string }[];

export function shadowRoutes(live: LiveReach | null, routes: Routes | null, earlier: readonly Routes[] = [], codeUnread = false): ShadowRoutes {
  if (!live) return { state: "unknown", why: "No app address is bound to this repository." };
  if (!live.requests) return { state: "unknown", why: "The live site has not been read since requests were recorded." };
  if (!routes) return { state: "unknown", why: "No audit of this repository stored its routes." };
  if (routes.length >= MAX_STORED) return { state: "unknown", why: "The repository has more routes than an audit stores." };
  const declared = declares(routes);
  const paths = live.requests.filter((p) => API_PATH.test(p) && !declared(p)).sort();
  const before = earlier.map(declares);
  const { scriptsSeen, scriptsRead } = live.read;
  return { state: "read", paths, partial: scriptsSeen === null || scriptsRead === null || scriptsRead < scriptsSeen,
    removed: paths.filter((p) => before.some((d) => d(p))), codeUnread };
}

// The audit's note when it skipped files or its archive was cut (lib/agent/audit.ts).
const FILES_UNREAD = /^\d+ files? we did not read$/;
type Run = { fullName: string; routeFacts: Routes | null; coverage: readonly { name: string }[] };

/** Shadow routes for one repository from stored runs (newest first): its
 * newest route facts, the earlier ones for drift, and whether that audit left
 * files unread, which makes a listed address possibly a route it never saw. */
export function shadowRoutesFromRuns(live: LiveReach | null, runs: readonly Run[], fullName: string): ShadowRoutes {
  const withRoutes = runs.filter((r) => r.fullName === fullName && r.routeFacts);
  return shadowRoutes(live, withRoutes[0]?.routeFacts ?? null, withRoutes.slice(1).map((r) => r.routeFacts!),
    withRoutes[0]?.coverage.some((c) => FILES_UNREAD.test(c.name)) ?? false);
}

/** Whether a set of route entries serves a requested path. */
function declares(routes: Routes): (path: string) => boolean {
  const matchers = routes.flatMap((r) => {
    if (r.path.startsWith("action:")) return [];
    if (r.path.startsWith("trpc:")) return [(p: string) => TRPC.test(p)];
    const matches = routeMatcher(r.path);
    const bare = r.path.startsWith("/") ? r.path : r.path.slice(r.path.indexOf(":/") + 1);
    // A request cut at a template hole ends in "/": any route under it serves it.
    return [(p: string) => (matches?.(p) ?? false) || (p.endsWith("/") && bare.startsWith(p))];
  });
  return (p) => matchers.some((m) => m(p));
}

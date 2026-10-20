import { routeMatcher } from "@/lib/graph/clientReach";

/**
 * Reach, observed on the live site (P5, the outside view): the paths the
 * JavaScript a visitor downloads names. The bundle audit already fetches
 * those scripts (lib/security/bundleAudit.ts); this keeps what they call so a
 * finding's reach link can say "your live site names it", which the
 * repository alone can only infer (lib/graph/clientReach.ts).
 *
 * Named, not called: a bundled third party SDK names paths on its own host
 * (PostHog's /api/surveys/ on shiplock.dev, 2026-10-17), so a match says the
 * address ships to every visitor, never that the site requests it.
 *
 * Paths only. A query string or fragment is cut, and anything that is not a
 * plain path is dropped, so no value from the customer's bundle is stored.
 * Reach only adds evidence: a path the bundle does not name is unknown, never
 * "not reachable", since attackers call APIs directly.
 */
export const MAX_PATHS = 500;
/** What one read of the live site saw: whether its page was read, how many
 * pages (it and the ones it links) answered, how many same-origin scripts they
 * list and how many were read, the paths named and those requested on the
 * site's own origin. */
export type ShippedRead = {
  pageRead: boolean; pagesRead: number; scriptsSeen: number; scriptsRead: number; paths: Set<string>; requests: Set<string>;
};
/** An address served by the app's backend rather than a page. */
export const API_PATH = /^\/(?:api|trpc|graphql|rpc)(?:\/|$)/;
const MAX_LENGTH = 200;
// A quoted path that runs to its closing quote or a template hole.
const PATH_LITERAL = /["'`](\/[^"'`\s$]*)(?=["'`]|\$\{)/g;
const PLAIN = /^\/[A-Za-z0-9_\-.~/[\]:@]+$/;
const ASSET = /^\/_next(?:\/|$)|\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|txt|xml|json)$/i;
const CATCH_ALL = /^\[\[?\.\.\./;

export function calledPaths(js: string): string[] {
  return plainPaths(js, () => true);
}

// A literal handed straight to a request: the first argument of fetch, an
// HTTP client verb, useSWR or new Request, or a url or href value. Built on
// any other base (endpointFor, this.url + "/x", pathname = "/x"), a path
// belongs to whatever host that base names, which is how bundled SDKs reach
// their own servers.
const REQUEST_CONTEXT = /(?:\bfetch|\.(?:get|post|put|patch|delete|head|request)|\buseSWR|\bnew Request)\(\s*$|\b(?:url|href)\s*[:=]\s*$/;

/** The paths the app itself requests on its own origin (shadow routes read these). */
export function requestedPaths(js: string): string[] {
  return plainPaths(js, (at) => REQUEST_CONTEXT.test(js.slice(Math.max(0, at - 24), at)));
}

function plainPaths(js: string, keep: (quoteAt: number) => boolean): string[] {
  const out = new Set<string>();
  for (const m of js.matchAll(PATH_LITERAL)) {
    const path = m[1].split(/[?#]/)[0];
    if (path.length < 2 || path.length > MAX_LENGTH || path.startsWith("//")) continue;
    if (!PLAIN.test(path) || ASSET.test(path) || !keep(m.index)) continue;
    out.add(path);
  }
  return [...out].sort().slice(0, MAX_PATHS);
}

/** The live path that reaches a route entry, or null. A catch-all at the
 * first dynamic segment matches nothing: any path under it would. */
export function liveCaller(entry: string, paths: readonly string[]): string | null {
  if (entry.startsWith("action:") || entry.startsWith("trpc:")) return null;
  const bare = entry.startsWith("/") ? entry : entry.slice(entry.indexOf(":/") + 1);
  const dynamic = bare.split("/").filter(Boolean).find((s) => s.startsWith("["));
  if (dynamic && CATCH_ALL.test(dynamic)) return null;
  const matches = routeMatcher(entry);
  return (matches && paths.find(matches)) ?? null;
}

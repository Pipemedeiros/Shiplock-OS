import type { RepoFile } from "@/lib/deep/githubScan";

/**
 * Reach, read from code: is an entry called by the app's own pages or
 * components? A link of the evidence chain (lib/chain/evidenceChain.ts): an
 * attacker starts from what the app hands every visitor, and the shipped
 * bundle is built from these files. The outside view (the shipped bundle and
 * its source maps, REA's idea) observes the same thing on the live app; this
 * reads it from the repository, so it works on any audit and was measured on
 * the labeled corpus.
 *
 * Measured (docs/evaluation/reach-experiment-2026-10-16.json): entries
 * nothing calls were still real 85% of the time, because attackers call APIs
 * directly. So reach only ever adds evidence; its absence never lowers a
 * finding.
 */
export type ReachEntry = { path: string; file: string; via?: readonly string[] };
export type Reach = { reached: boolean; by: string[] };
export type ReachIndex = { literals: { text: string; file: string }[]; trpcCalls: Map<string, Set<string>> };

const MAX_BY = 5;
const NOT_SHIPPED = /(^|\/)(__tests__|tests?|e2e|cypress|playwright|scripts|supabase|prisma|migrations|seed)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$/;
const CODE = /\.[cm]?[jt]sx?$/;
const DYNAMIC = /^\[\[?(\.\.\.)?[^\]]+\]\]?$/;
// A quoted path: its text up to the closing quote, or up to a template hole.
const PATH_LITERAL = /["'`](\/[^"'`\s$]*)/g;
const TRPC_CALL = /\.([A-Za-z_$][\w$]*)\.(?:useQuery|useSuspenseQuery|useInfiniteQuery|useSuspenseInfiniteQuery|useMutation|query|mutate|mutateAsync|queryOptions|mutationOptions|infiniteQueryOptions|prefetch|fetch)\b/g;

/** One pass over the files the app ships; routes are then looked up, not rescanned. */
export function buildReachIndex(files: readonly RepoFile[]): ReachIndex {
  const literals: ReachIndex["literals"] = [];
  const trpcCalls = new Map<string, Set<string>>();
  for (const file of files) {
    if (!CODE.test(file.path) || NOT_SHIPPED.test(file.path)) continue;
    for (const m of file.content.matchAll(PATH_LITERAL)) literals.push({ text: m[1], file: file.path });
    for (const m of file.content.matchAll(TRPC_CALL)) {
      if (!trpcCalls.has(m[1])) trpcCalls.set(m[1], new Set());
      trpcCalls.get(m[1])!.add(file.path);
    }
  }
  return { literals, trpcCalls };
}

export function routeMatcher(path: string): ((text: string) => boolean) | null {
  // A duplicated route is named "<app root or file>:/path" (routeInventory).
  const bare = path.startsWith("/") ? path : path.slice(path.indexOf(":/") + 1);
  const segments = bare.split("/").filter(Boolean);
  if (segments.length === 0) return null;
  const firstDynamic = segments.findIndex((s) => DYNAMIC.test(s));
  if (firstDynamic === -1) {
    const whole = "/" + segments.join("/");
    return (t) => t === whole || t === whole + "/" || t.startsWith(whole + "?") || t.startsWith(whole + "#");
  }
  const prefix = "/" + segments.slice(0, firstDynamic).join("/") + "/";
  return (t) => t.startsWith(prefix);
}

export function reachOf(entry: ReachEntry, index: ReachIndex): Reach {
  const done = (files: Iterable<string>) => {
    const by = [...new Set(files)].filter((f) => f !== entry.file && !NOT_SHIPPED.test(f)).sort();
    return { reached: by.length > 0, by: by.slice(0, MAX_BY) };
  };
  if (entry.path.startsWith("action:")) return done(entry.via ?? []);
  if (entry.path.startsWith("trpc:")) return done(index.trpcCalls.get(entry.path.slice(entry.path.lastIndexOf("#") + 1)) ?? []);
  const matches = routeMatcher(entry.path);
  if (!matches) return { reached: false, by: [] };
  return done(index.literals.filter((l) => matches(l.text)).map((l) => l.file));
}

export function reachFromCode(entry: ReachEntry, files: readonly RepoFile[]): Reach {
  return reachOf(entry, buildReachIndex(files));
}

/** Every route with the shipped files that call it, from one index. */
export function withReach<R extends ReachEntry>(routes: readonly R[], files: readonly RepoFile[]): (R & { calledBy: string[] })[] {
  const index = buildReachIndex(files);
  return routes.map((r) => ({ ...r, calledBy: reachOf(r, index).by }));
}

import type { RepoFile } from "@/lib/deep/githubScan";
import { reachableSources, type RouteFact } from "./routeInventory";

// C6 — is the vulnerable code actually reachable?
//
// The single biggest noise reducer available to us, and also the single easiest
// place to do real harm, so the governing rule is stated first:
//
//   REACHABILITY MAY DOWNRANK AND EXPLAIN. IT MAY NEVER SILENTLY HIDE.
//
// Suppressing a real vulnerability because a regex-level walk failed to find a
// path to it is the same mistake as reporting a missing DNS record as "no
// finding" because the lookup threw — absence of evidence treated as evidence of
// absence. We cannot resolve dynamic imports, string-built require paths,
// re-exports through barrels, or anything called by a framework convention we
// don't know. So "we found no path" is reported as exactly that, and the finding
// stays on the board.
//
// What this buys, honestly: a founder with 40 findings has no idea which four
// matter. Telling them "this XSS sink is in a build script that never runs in
// production, and this one is in the file your signup page renders" is the
// difference between a list and a plan.

export type ReachabilityState = "reachable" | "no_path_found" | "unknown";

export interface ReachabilityVerdict {
  state: ReachabilityState;
  /** Shown to the customer. Plain, and honest about confidence. */
  reason: string;
  /** Ranking adjustment. Positive promotes, negative demotes. Never hides. */
  scoreDelta: number;
}

/**
 * Files that can begin an execution path in a Next.js app.
 *
 * Deliberately generous. A missed entry point makes live code look dead, which
 * is the dangerous direction — it would demote a real finding. An extra entry
 * point only makes dead code look live, which merely forgoes a noise reduction.
 */
// Next.js invokes these by FILE CONVENTION, at any depth including the app/
// root. Enumerated from the framework's own special-file list rather than
// guessed, because dogfooding found the guessed version calling app/robots.ts,
// app/sitemap.ts and app/opengraph-image.tsx dead — all three run in production.
// That is the dangerous direction: live code looking dead demotes a real
// finding, while dead code looking live merely forgoes a noise reduction.
const NEXT_SPECIAL_FILES =
  "page|layout|template|loading|error|global-error|not-found|route|default|robots|sitemap|manifest|icon|apple-icon|opengraph-image|twitter-image|actions";

const ENTRY_POINT_RE = new RegExp(
  `^(src/)?(` +
    // app/**/<special>.<ext>, at any depth including the root
    `app/([^?]*/)?(${NEXT_SPECIAL_FILES})\\.(ts|tsx|js|jsx)` +
    `|pages/.*\\.(ts|tsx|js|jsx)` +
    `|(middleware|instrumentation)\\.(ts|js)` +
    `)$`
);

/** Paths that are plainly not production code paths. */
const NON_PRODUCTION_RE =
  /(^|\/)(__tests__|__mocks__|test|tests|e2e|cypress|playwright|spec|scripts|tools|examples?|docs?|fixtures?|storybook|\.storybook)\//i;
const TEST_FILE_RE = /\.(test|spec)\.(ts|tsx|js|jsx)$/i;

export function isEntryPoint(path: string): boolean {
  return ENTRY_POINT_RE.test(path);
}

export function isNonProductionPath(path: string): boolean {
  return NON_PRODUCTION_RE.test(path) || TEST_FILE_RE.test(path);
}

export interface ReachabilityContext {
  /** Every file we read, for the import walk. */
  files: RepoFile[];
  /** Route facts, for table-exposure questions. */
  routes: RouteFact[];
}

export interface ReachabilityIndex {
  /** Files reachable from at least one entry point. */
  liveFiles: Set<string>;
  /** Whether we found any entry points at all — if not, every verdict is unknown. */
  hasEntryPoints: boolean;
  /** Tables referenced by at least one route. */
  exposedTables: Set<string>;
}

/**
 * Walks every entry point's imports to find the live set.
 *
 * When a repo yields NO entry points — because the file cap truncated them, or
 * it isn't a Next.js app, or we only read part of it — every verdict becomes
 * `unknown`. That is the important safeguard: with no entry points, every file
 * looks unreachable, and we would demote the entire finding list at once.
 */
export function buildReachabilityIndex(ctx: ReachabilityContext): ReachabilityIndex {
  const byPath = new Map(ctx.files.map((f) => [f.path, f]));
  const entries = ctx.files.filter((f) => isEntryPoint(f.path));
  const liveFiles = new Set<string>();

  for (const entry of entries) {
    for (const { path } of reachableSources(entry, byPath)) liveFiles.add(path);
  }

  const exposedTables = new Set<string>();
  for (const route of ctx.routes) {
    for (const table of route.tables) {
      exposedTables.add(table.startsWith("rpc:") ? table : table.replace(/^public\./, ""));
    }
  }

  return { liveFiles, hasEntryPoints: entries.length > 0, exposedTables };
}

/** Pulls the file path out of a finding id, if it carries one. */
export function fileFromFindingId(id: string): string | null {
  // Ids look like `owner/name::github:xss_sink:eval_call:app/api/x/route.ts`.
  const withoutRepo = id.includes("::") ? id.slice(id.indexOf("::") + 2) : id;
  const parts = withoutRepo.split(":");
  const last = parts[parts.length - 1];
  return /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(last) ? last : null;
}

/** Pulls the table name out of a policy/advisor finding id, if it carries one. */
export function tableFromFindingId(id: string): string | null {
  const m = /^(?:policy|advisor):[^:]*:?([\w]+\.[\w]+)$/.exec(id) ?? /^policy:([\w]+\.[\w]+):/.exec(id);
  return m ? m[1].replace(/^public\./, "") : null;
}

const UNKNOWN: ReachabilityVerdict = {
  state: "unknown",
  reason: "",
  scoreDelta: 0,
};

/**
 * Judges one finding.
 *
 * Every `no_path_found` verdict says WHAT we looked for and admits what would
 * change the answer, because a founder who cannot check our reasoning has to
 * take it on faith — and this is precisely the judgement where being wrong is
 * expensive.
 */
export function assessReachability(
  findingId: string,
  index: ReachabilityIndex
): ReachabilityVerdict {
  if (!index.hasEntryPoints) return UNKNOWN;

  const file = fileFromFindingId(findingId);
  if (file) {
    if (isNonProductionPath(file)) {
      return {
        state: "no_path_found",
        reason: `This is in ${file}, which is test or tooling code rather than something your app serves. Still worth fixing, but it is not exposed to your users, so it should not compete for attention with the findings that are.`,
        scoreDelta: -40,
      };
    }
    if (index.liveFiles.has(file)) {
      return {
        state: "reachable",
        reason: `${file} is reachable from a page or API route your app serves, so this code really does run for real requests.`,
        scoreDelta: 20,
      };
    }
    return {
      state: "no_path_found",
      reason: `We could not find a path from any page, API route or middleware to ${file}. That usually means it is unused, but our import following does not resolve dynamically-built paths or every framework convention — so treat this as "probably not live" rather than proven dead. If it is genuinely unused, deleting it is the cleanest fix.`,
      scoreDelta: -25,
    };
  }

  const table = tableFromFindingId(findingId);
  if (table) {
    if (index.exposedTables.has(table)) {
      return {
        state: "reachable",
        reason: `Your API reads ${table}, so a permissive policy on it is reachable from the internet rather than theoretical.`,
        scoreDelta: 25,
      };
    }
    return {
      state: "no_path_found",
      reason: `No API route we can see reads ${table}. The policy is still wrong and still worth fixing — anything holding your anon key could use it directly — but nothing in your own code is currently exposing this table, so it is less urgent than the ones that are.`,
      scoreDelta: -15,
    };
  }

  return UNKNOWN;
}

export interface TriageableFinding {
  id: string;
  severity: string;
  title: string;
}

export interface TriagedFinding<T extends TriageableFinding> {
  finding: T;
  reachability: ReachabilityVerdict;
  rank: number;
}

const SEVERITY_BASE: Record<string, number> = { CRITICAL: 100, WARNING: 50, INFO: 20 };

/**
 * Orders findings by severity ADJUSTED for reachability, and attaches the
 * reasoning.
 *
 * Nothing is removed. The output length always equals the input length — a
 * property worth asserting in tests, because the temptation to quietly drop the
 * bottom of the list is exactly what would make this feature dangerous.
 */
export function triageByReachability<T extends TriageableFinding>(
  findings: T[],
  index: ReachabilityIndex
): TriagedFinding<T>[] {
  return findings
    .map((finding) => {
      const reachability = assessReachability(finding.id, index);
      return {
        finding,
        reachability,
        rank: (SEVERITY_BASE[finding.severity] ?? 30) + reachability.scoreDelta,
      };
    })
    .sort((a, b) => b.rank - a.rank || a.finding.id.localeCompare(b.finding.id));
}

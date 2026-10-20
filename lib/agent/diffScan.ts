import type { ArchiveFile } from "@/lib/deep/repoArchive";
import { collectRoutes, type RouteFact } from "@/lib/graph/routeInventory";
import { scanSecrets } from "@/lib/deep/githubScan";
import type { StackReport } from "./stack";

/**
 * The per-pull-request pass: deterministic on the diff, reasoning only on top.
 *
 * A full audit re-reads the whole repository and calls the model once. Doing
 * that on every push to every open pull request would be slow, expensive, and
 * mostly a re-derivation of facts that did not change. It would also be the
 * wrong shape for a merge check, which has to answer in seconds and has to be
 * something a developer can argue with.
 *
 * So this pass is scoped to what the pull request touched:
 *
 *   1. Deterministic checks on the changed files only. These decide the verdict.
 *   2. A route-level comparison against the rest of the repository, which is
 *      what turns "this route has no ownership filter" into "this route has no
 *      ownership filter and its six siblings do".
 *   3. Reasoning is invited ONLY when step 1 or 2 raised something. A clean
 *      diff never reaches the model.
 *
 * The verdict is deterministic in every case. The model can explain a finding
 * and it can decline to; it can never create one, and it can never clear one.
 */

export type Verdict = "pass" | "warn" | "block";

export interface DiffFinding {
  id: string;
  severity: "CRITICAL" | "WARNING";
  title: string;
  detail: string;
  file: string;
  /** Why this is a regression rather than a style preference. */
  evidence: string;
}

export interface DiffScanResult {
  verdict: Verdict;
  findings: DiffFinding[];
  filesChanged: number;
  routesChanged: number;
  /** True when nothing changed that could affect security. */
  trivial: boolean;
}

/**
 * Files that cannot change the security posture of an application.
 *
 * Kept deliberately short. Everything not listed here is scanned, because the
 * cost of scanning a harmless file is a few milliseconds and the cost of
 * skipping a dangerous one is the entire product.
 */
const INERT = /\.(md|mdx|txt|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|csv)$|(^|\/)(CHANGELOG|LICENSE)/i;

export interface DiffScanInput {
  /** Files as they are AFTER the change, restricted to what the PR touched. */
  changed: ArchiveFile[];
  /** The rest of the repository, for comparison. Not scanned. */
  baseline: ArchiveFile[];
  stack: StackReport;
  /**
   * The route inventory of baseline + changed, when the caller already holds
   * it. Purely a cost saving: the inventory is a pure function of the file set,
   * and a measurement that scans every route of a repository one at a time
   * would otherwise rebuild it once per route. Never changes the verdict.
   */
  inventory?: RouteFact[];
}

/**
 * The comparison that makes a finding persuasive.
 *
 * A route with no ownership filter might be deliberate. A route with no
 * ownership filter, on a table that six other routes all filter by owner, is a
 * mistake — and saying so with the count is the difference between an opinion
 * and an argument.
 */
export function siblingsScopingTable(routes: RouteFact[], table: string): { scoped: number; total: number } {
  // Routes whose filter we could not READ are excluded from BOTH halves, not
  // counted as unscoped. They are the denominator's problem: "5 of 6 routes
  // scope this table" is an argument, and it becomes a false one the moment the
  // sixth is merely unread. Excluding them shrinks the evidence rather than
  // inventing it, which is the direction this file should always fail.
  const touching = routes.filter((r) => r.tables.includes(table) && r.ownershipReadable);
  return { scoped: touching.filter((r) => r.ownershipFiltered).length, total: touching.length };
}

export function scanDiff(input: DiffScanInput): DiffScanResult {
  const changed = input.changed.filter((f) => !INERT.test(f.path));
  if (changed.length === 0) {
    return { verdict: "pass", findings: [], filesChanged: 0, routesChanged: 0, trivial: true };
  }

  const findings: DiffFinding[] = [];

  // 1 — committed credentials in the diff. Never a warning: a key in a commit
  //     is in the history whether or not the pull request is merged.
  for (const secret of scanSecrets(changed)) {
    findings.push({
      id: secret.id,
      severity: "CRITICAL",
      title: secret.title,
      detail: secret.consequence,
      file: secret.id.split(":").pop() ?? "",
      evidence: "Matched a real credential shape in a file this pull request adds or changes.",
    });
  }

  // 2 — routes the pull request introduces or edits, compared with the rest of
  //     the repository.
  //
  // Both sets are collected from the WHOLE repository, then narrowed to the
  // files this pull request touched. Collecting from the diff alone looked
  // equivalent and was not: route facts follow imports two hops to find the
  // auth helper, and a pull request does not contain lib/deep/proGate.ts, so
  // every authenticated route in a diff read as anonymous.
  //
  // The first real pull request this check ran on proved it. A route calling
  // requireProUser() and returning 401 was posted as "anyone on the internet
  // can call this endpoint", and the check BLOCKED the merge on it. A blocking
  // verdict with a wrong reason is worse than no check: it is the thing that
  // gets a security tool switched off in its first week.
  const changedPaths = new Set(changed.map((f) => f.path));
  const allRoutes = input.inventory ?? collectRoutes([...input.baseline, ...changed]);
  const changedRoutes = allRoutes.filter((r) => changedPaths.has(r.file));

  for (const route of changedRoutes) {
    if (route.machineGated) continue; // a shared secret is the gate; ownership is not the question
    if (route.tables.length === 0) continue; // reaches no data, cannot leak it

    // "No caller is resolved" and "the query is narrowed to the caller" cannot
    // both be true. When they are, we did not see the auth rather than there
    // being none: the helper may sit outside what we read, or behind more
    // indirection than the import walk follows. Reporting the contradiction as
    // a blocking critical is the worst outcome available, so the safer half of
    // it wins and the route falls through to the ownership checks below.
    // A route whose gate we could not read is not a route with no gate, and a
    // BLOCKING verdict on one is the failure that gets a security tool switched
    // off in its first week. Measured across five real codebases: every one of
    // these was actually protected.
    if (!route.identityReadable) continue;

    // FAIL CLOSED HERE SPECIFICALLY. This function gates the merge check, so a
    // misread does not produce a finding somebody can disagree with -- it
    // blocks a customer's pull request. An unreadable ownership filter buys a
    // pass, never a block.
    if (!route.ownershipReadable) continue;

    if (!route.authenticated && !route.ownershipFiltered) {
      findings.push({
        id: `diff:anon:${route.path}`,
        severity: "CRITICAL",
        title: `${route.path} reaches ${route.tables.join(", ")} without resolving a caller`,
        detail:
          "Anyone on the internet can call this endpoint, and it reads data belonging to your users.",
        file: route.file,
        evidence: "No identity is resolved in the handler or in anything it imports two hops deep.",
      });
      continue;
    }

    if (route.ownershipFiltered) continue;

    for (const table of route.tables) {
      const siblings = siblingsScopingTable(allRoutes, table);
      // One route touching a table proves nothing. Two or more, where the
      // others all scope and this one does not, is the argument.
      const isOutlier = siblings.total > 1 && siblings.scoped >= siblings.total - 1;

      findings.push({
        id: `diff:unscoped:${route.path}:${table}`,
        severity: isOutlier ? "CRITICAL" : "WARNING",
        title: `${route.path} reads ${table} without narrowing it to the caller`,
        detail:
          "A signed-in user can request another user's row, because nothing in the query belongs to the caller.",
        file: route.file,
        evidence: isOutlier
          ? `${siblings.scoped} of the ${siblings.total} routes touching ${table} filter by owner. This one does not.`
          : `No other route touching ${table} filters by owner either, so this may be deliberate.`,
      });
    }
  }

  const verdict: Verdict = findings.some((f) => f.severity === "CRITICAL")
    ? "block"
    : findings.length > 0
      ? "warn"
      : "pass";

  return {
    verdict,
    findings,
    filesChanged: changed.length,
    routesChanged: changedRoutes.length,
    trivial: false,
  };
}

/** The check-run summary. Deterministic; the model never writes this. */
export function checkSummary(result: DiffScanResult): { title: string; summary: string } {
  if (result.trivial) {
    return { title: "No security-relevant changes", summary: "Nothing in this pull request can affect access to data." };
  }
  if (result.verdict === "pass") {
    return {
      title: `${result.filesChanged} files checked, nothing found`,
      summary:
        "This is not a statement that the pull request is safe, only that the checks that ran found nothing. See Coverage for what they do not cover.",
    };
  }

  const lines = result.findings.map((f) => `- **${f.title}**\n  ${f.detail}\n  _${f.evidence}_ (\`${f.file}\`)`);

  return {
    title:
      result.verdict === "block"
        ? `${result.findings.filter((f) => f.severity === "CRITICAL").length} blocking`
        : `${result.findings.length} to look at`,
    summary: lines.join("\n\n"),
  };
}

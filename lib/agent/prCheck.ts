import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createCheckRun,
  getInstallationToken,
  getPullRequest,
  listPullRequestFiles,
} from "@/lib/deep/github";
import { fetchRepoArchive } from "@/lib/deep/repoArchive";
import { detectStack } from "./stack";
import { checkGuardrails, deriveGuardrails } from "@/lib/guardrails/guardrails";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { checkSummary, scanDiff, type DiffScanResult } from "./diffScan";

/**
 * The merge check.
 *
 * This is the thing that makes ShipLock part of the workflow rather than
 * another dashboard: the answer arrives on the pull request, before the merge,
 * where the decision is actually made.
 *
 * It runs the DIFF pass, not a full audit — seconds rather than minutes, and
 * scoped to what the pull request touched. The verdict is deterministic. The
 * conclusion posted to GitHub is `neutral` for anything short of a finding we
 * would defend to the author's face, because a security tool that blocks merges
 * on a guess gets switched off within a week.
 */

export interface PrCheckResult {
  posted: boolean;
  verdict: DiffScanResult["verdict"];
  findings: number;
  skipped?: string;
}

/** What one PR check found, stored for the dashboard, alerts, and a
 * before-merge fix. PR metadata is null when GitHub did not return it. */
export interface PullRequestReview {
  pullRequestNumber: number;
  headSha: string;
  headRef: string | null;
  headRepository: string | null;
  sameRepository: boolean | null;
  title: string | null;
  url: string | null;
  verdict: DiffScanResult["verdict"];
  coverageComplete: boolean;
  findings: Pick<DiffScanResult["findings"][number], "id" | "severity" | "title" | "detail" | "file" | "evidence">[];
}

/** Checks one pull request head on a repository the customer selected and
 * stores the review under the job's lease. A partial read is never a pass. */
export async function runPullRequestCheck(options: {
  userId: string;
  installationId: number;
  fullName: string;
  prNumber: number;
  headSha: string;
  /** Stores the review under the PR-check job's lease; throws if fenced out. */
  persistReview: (review: PullRequestReview) => Promise<void>;
}): Promise<PrCheckResult> {
  const { userId, installationId, fullName, prNumber, headSha, persistReview } = options;
  const admin = getSupabaseAdmin();

  // Only repositories the customer chose. An installation can see more than it
  // was asked to audit, and checking an unselected repo is work nobody wanted.
  const { data: repo, error: repositoryError } = await admin
    .from("repositories")
    .select("id")
    .eq("user_id", userId)
    .eq("full_name", fullName)
    .eq("selected", true)
    .maybeSingle();

  if (repositoryError) throw new Error("Selected repository could not be read");
  if (!repo) return { posted: false, verdict: "pass", findings: 0, skipped: "repository not selected" };

  const token = await getInstallationToken(installationId);
  const diff = await listPullRequestFiles(token, fullName, prNumber, headSha);
  const changed = diff.files;

  // The baseline is the repository as it stands, used ONLY for comparison —
  // "six sibling routes scope this table and yours does not" is the sentence
  // that turns a lint into an argument. It is never scanned itself, so nothing
  // pre-existing is reported as this pull request's fault.
  const archive = await fetchRepoArchive(token, fullName).catch(() => null);
  const baseline = archive?.files.filter((f) => !changed.some((c) => c.path === f.path)) ?? [];

  // The controls the default branch has today are guardrails. A change
  // that removes one from a route it touches blocks, whatever else it does.
  const afterRoutes = collectRoutes([...baseline, ...changed]);
  const guardrails = deriveGuardrails(archive ? collectRoutes(archive.files) : [], { repository: fullName, commit: null });
  const guard = checkGuardrails(guardrails, afterRoutes, new Set(changed.map((file) => file.path)));

  const scanned = scanDiff({
    changed,
    baseline,
    stack: detectStack(archive?.files ?? changed),
    inventory: afterRoutes,
  });
  const result = guard.violations.length === 0 ? scanned : {
    ...scanned,
    verdict: "block" as const,
    findings: [
      ...guard.violations.map((v) => ({ id: `guardrail:${v.id}`, severity: v.severity, title: `Removes a control: ${v.route}`,
        detail: v.detail, file: v.file, evidence: v.because })),
      ...scanned.findings,
    ],
  };

  const base = checkSummary(result);
  const coverageComplete = diff.complete && archive !== null && guard.unread.length === 0;
  const title = coverageComplete ? base.title : `Partial review: ${base.title}`;
  const coverage = [diff.coverage, archive ? "Repository baseline was readable." : "Repository baseline was unreadable; cross-file route context is incomplete.",
    ...(guard.unread.length ? [`We could not confirm ${guard.unread.length} existing control${guard.unread.length === 1 ? "" : "s"} after this change: ${guard.unread.join(", ")}.`] : [])].join("\n\n");
  const summary = `${base.summary}\n\n### Coverage\n${coverage}`;
  // A partial read can retain a concrete deterministic failure, but may never
  // report success. Neutral is the honest state for a clean or warning-only
  // partial review.
  const conclusion = result.verdict === "block"
    ? "failure"
    : result.verdict === "warn" || !coverageComplete
      ? "neutral"
      : "success";

  // Store the review first, so the dashboard and alerts never lag a posted
  // check. A failed store throws before posting and the job retries.
  const meta = await getPullRequest(token, fullName, prNumber).catch(() => null);
  await persistReview({
    pullRequestNumber: prNumber, headSha: headSha.toLowerCase(),
    headRef: meta?.headRef ?? null, headRepository: meta?.headRepository ?? null,
    sameRepository: meta?.sameRepository ?? null, title: meta?.title ?? null, url: meta?.url ?? null,
    verdict: result.verdict, coverageComplete,
    findings: result.findings.slice(0, 100).map(({ id, severity, title, detail, file, evidence }) =>
      ({ id, severity, title, detail, file, evidence })),
  });

  await createCheckRun(
    token,
    fullName,
    headSha,
    conclusion,
    title,
    summary,
    `shiplock:pr:${fullName}:${prNumber}:${headSha.toLowerCase()}`,
  );

  return { posted: true, verdict: result.verdict, findings: result.findings.length };
}

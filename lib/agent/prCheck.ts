import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createCheckRun,
  getInstallationToken,
  listPullRequestFiles,
} from "@/lib/deep/github";
import { fetchRepoArchive } from "@/lib/deep/repoArchive";
import { detectStack } from "./stack";
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

export async function runPullRequestCheck(options: {
  userId: string;
  installationId: number;
  fullName: string;
  prNumber: number;
  headSha: string;
}): Promise<PrCheckResult> {
  const { userId, installationId, fullName, prNumber, headSha } = options;
  const admin = getSupabaseAdmin();

  // Only repositories the customer chose. An installation can see more than it
  // was asked to audit, and checking an unselected repo is work nobody wanted.
  const { data: repo } = await admin
    .from("repositories")
    .select("id")
    .eq("user_id", userId)
    .eq("full_name", fullName)
    .eq("selected", true)
    .maybeSingle();

  if (!repo) return { posted: false, verdict: "pass", findings: 0, skipped: "repository not selected" };

  const token = await getInstallationToken(installationId);
  const changed = await listPullRequestFiles(token, fullName, prNumber, headSha);

  if (changed.length === 0) {
    return { posted: false, verdict: "pass", findings: 0, skipped: "no readable files in the diff" };
  }

  // The baseline is the repository as it stands, used ONLY for comparison —
  // "six sibling routes scope this table and yours does not" is the sentence
  // that turns a lint into an argument. It is never scanned itself, so nothing
  // pre-existing is reported as this pull request's fault.
  const archive = await fetchRepoArchive(token, fullName).catch(() => null);
  const baseline = archive?.files.filter((f) => !changed.some((c) => c.path === f.path)) ?? [];

  const result = scanDiff({
    changed,
    baseline,
    stack: detectStack(archive?.files ?? changed),
  });

  const { title, summary } = checkSummary(result);

  await createCheckRun(
    token,
    fullName,
    headSha,
    result.verdict === "block" ? "failure" : result.verdict === "warn" ? "neutral" : "success",
    title,
    summary,
  );

  return { posted: true, verdict: result.verdict, findings: result.findings.length };
}

import { getSupabaseAdmin } from "@/lib/supabase";
import {
  getInstallationToken,
  getBranchSha,
  createBranch,
  putFile,
  openPullRequest,
} from "@/lib/deep/github";
import type { DashboardFinding } from "./dashboardData";
import { fixBranchName, fixFilePath, fixTitle, fixDocument } from "./fixPr";

/**
 * Opens the fix pull requests itself, at the end of an audit.
 *
 * This is the difference between a security tool and a security engineer, and
 * it is the whole product promise: the customer does not get a queue of work to
 * do, they get a queue of work to APPROVE. A finding that requires them to find
 * a button, press it, and wait has already spent the attention we were supposed
 * to save. Anything ending in "...and then you go do it" has failed the brief.
 *
 * What "autonomous" does NOT mean here, and must never come to mean:
 *
 *   - We never merge. Every pull request is opened on a branch of its own, off
 *     the default branch, and it sits there until a human approves it. The
 *     customer's merge button is the only thing that changes their code.
 *   - We never push to the default branch, and we never touch an existing
 *     branch. A new branch per finding, or nothing.
 *   - We never machine-author authorization logic. Which column identifies a
 *     tenant is intent that lives in the customer's head, so the pull request
 *     carries the finding, the evidence ledger and a precise instruction --
 *     the same body a human reviewer would want -- and their coding agent or
 *     their hands finish it.
 *
 * So the autonomy is in the OPENING, not in the authorship. That is the honest
 * version of the promise, and it is the version that survives being wrong.
 */

/** Never open more than this many in a single run. */
const MAX_PRS_PER_RUN = 5;

export interface AutoFixOutcome {
  opened: { findingId: string; url: string; number: number | null }[];
  skipped: { findingId: string; reason: string }[];
  failed: { findingId: string; error: string }[];
}

/**
 * Which findings get a pull request opened for them without being asked.
 *
 * Three gates, and all three are deliberate:
 *
 *   fixKind === "pr"  — the finding's own autonomy tier. A `manual` finding is
 *                       a decision about the customer's architecture, and
 *                       opening a pull request about it would be noise wearing
 *                       the shape of help.
 *   no PR already     — idempotency. An audit runs every 48 hours and on every
 *                       push; a finding that survives must not accumulate a
 *                       pull request per run.
 *   severity          — CRITICAL and WARNING only. We do not spend a customer's
 *                       review attention on an INFO.
 */
export function selectForAutoPr(findings: DashboardFinding[]): DashboardFinding[] {
  return findings
    .filter((f) => f.fixKind === "pr")
    .filter((f) => !f.fixPrUrl)
    .filter((f) => f.severity === "CRITICAL" || f.severity === "WARNING")
    .filter((f) => Boolean(f.repository))
    // Worst first: if the cap truncates, it must truncate the least important
    // end. A run that opens five pull requests and drops the critical one has
    // inverted its own priority.
    .sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "CRITICAL" ? -1 : 1))
    .slice(0, MAX_PRS_PER_RUN);
}

/**
 * Opens a pull request for each qualifying finding.
 *
 * Failures are collected, never thrown. A GitHub outage, a repository that
 * revoked our access, a branch name that already exists -- none of those are
 * reasons to fail an audit that has already done its work and found real
 * things. The audit's value is the findings; the pull requests are delivery,
 * and delivery degrades on its own.
 */
export async function openFixPullRequests(
  userId: string,
  findings: DashboardFinding[],
): Promise<AutoFixOutcome> {
  const outcome: AutoFixOutcome = { opened: [], skipped: [], failed: [] };
  const chosen = selectForAutoPr(findings);

  for (const f of findings) {
    if (!chosen.includes(f) && f.fixKind === "pr" && f.fixPrUrl) {
      outcome.skipped.push({ findingId: f.id, reason: "a pull request is already open" });
    }
  }

  if (chosen.length === 0) return outcome;

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId) {
    for (const f of chosen) outcome.skipped.push({ findingId: f.id, reason: "GitHub is not connected" });
    return outcome;
  }

  let token: string;
  try {
    token = await getInstallationToken(installationId);
  } catch (err) {
    for (const f of chosen) {
      outcome.failed.push({ findingId: f.id, error: err instanceof Error ? err.message : "GitHub token failed" });
    }
    return outcome;
  }

  for (const finding of chosen) {
    try {
      const { data: repoRow } = await admin
        .from("repositories")
        .select("default_branch")
        .eq("user_id", userId)
        .eq("full_name", finding.repository as string)
        .maybeSingle();

      const base = (repoRow?.default_branch as string) ?? "main";
      const branch = fixBranchName(finding.id);
      const sha = await getBranchSha(token, finding.repository as string, base);

      await createBranch(token, finding.repository as string, branch, sha);
      await putFile(
        token,
        finding.repository as string,
        fixFilePath(finding.id),
        branch,
        fixDocument(finding),
        undefined,
        `ShipLock: ${finding.title}`,
      );

      const url = await openPullRequest(
        token,
        finding.repository as string,
        branch,
        base,
        fixTitle(finding),
        fixDocument(finding),
      );

      const parsed = Number(url.split("/").pop());
      const number = Number.isFinite(parsed) ? parsed : null;

      await admin
        .from("deep_findings")
        .update({ fix_pr_url: url, fix_pr_number: number })
        .eq("id", finding.rowId);

      outcome.opened.push({ findingId: finding.id, url, number });
    } catch (err) {
      // One repository's failure must not stop the next one's pull request.
      const message = err instanceof Error ? err.message : "unknown error";
      console.error(`[autoFixPr] ${finding.id}: ${message}`);
      outcome.failed.push({ findingId: finding.id, error: message });
    }
  }

  return outcome;
}

import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createBranch, findOpenPullRequestForBranch, getBranchSha, getInstallationToken, openPullRequest, putFile,
} from "@/lib/deep/github";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { fixBranchName, fixDocument, fixFilePath, fixTitle } from "@/lib/agent/fixPr";
import { openedOutcome, type RepairOutcome } from "./repairOutcome";

/**
 * Opens the fix PR for one Risks-board finding, inside a repair job.
 * Always a NEW branch off the default, never a push to the default itself and
 * never a merge. The branch name is deterministic per finding, so a retry after
 * an uncertain delivery finds the PR it already opened instead of a second one.
 */
export async function openRiskFixPr(userId: string, findingId: string, repositoryId: string): Promise<RepairOutcome> {
  // Read the finding from OUR record, never the request: title, evidence, and
  // the file that lands in the customer's repository all come from the row.
  const finding = (await getOpenFindings(userId)).find((f) => f.id === findingId);
  if (!finding) return { status: "failed", code: "finding_unavailable" };
  if (finding.fixKind === "manual") return { status: "failed", code: "not_fixable" };
  if (finding.fixPrUrl) return openedOutcome(finding.fixPrUrl);

  const admin = getSupabaseAdmin();
  const [{ data: profile }, { data: repoRow }] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id").eq("id", userId).single(),
    admin.from("repositories").select("full_name, default_branch")
      .eq("id", repositoryId).eq("user_id", userId).eq("selected", true).maybeSingle(),
  ]);
  const installationId = profile?.github_installation_id as number | null;
  if (!installationId || !repoRow || repoRow.full_name !== finding.repository) {
    return { status: "failed", code: "repository_unavailable" };
  }

  const repository = repoRow.full_name as string;
  const token = await getInstallationToken(installationId);
  const branch = fixBranchName(finding.id);
  let url = await findOpenPullRequestForBranch(token, repository, branch);
  if (!url) {
    const base = repoRow.default_branch as string;
    const existing = await getBranchSha(token, repository, branch).then(() => true, () => false);
    if (!existing) await createBranch(token, repository, branch, await getBranchSha(token, repository, base));
    await putFile(token, repository, fixFilePath(finding.id), branch, fixDocument(finding), undefined, `ShipLock: ${finding.title}`);
    url = await openPullRequest(token, repository, branch, base, fixTitle(finding), fixDocument(finding));
  }
  const outcome = openedOutcome(url);
  if (outcome.status === "opened") {
    await admin.from("deep_findings")
      .update({ fix_pr_url: outcome.url, fix_pr_number: outcome.number })
      .eq("id", finding.rowId);
  }
  return outcome;
}

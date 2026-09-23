import { createHash } from "node:crypto";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createBranch, findOpenPullRequestForBranch, getBranchSha, getInstallationToken, openPullRequest, putFile,
} from "@/lib/deep/github";
import { openedOutcome, type RepairOutcome } from "./repairOutcome";

const findingSchema = z.object({
  id: z.string(), severity: z.string(), title: z.string(), detail: z.string(), file: z.string(), evidence: z.string(),
});
type ReviewFinding = z.infer<typeof findingSchema>;
const reviewSchema = z.object({
  pull_request_number: z.number().int().positive(), head_ref: z.string().nullable(),
  same_repository: z.boolean().nullable(), findings: z.array(findingSchema),
  repositories: z.object({ full_name: z.string() }),
});

/** What to change, by finding kind. Authorization and ownership stay a human
 * decision (AGENTS.md), so this names the change rather than authoring it. */
function instruction(finding: ReviewFinding): string {
  if (finding.id.startsWith("diff:anon:")) {
    return "Resolve the signed-in caller before this handler reads any data, and return 401 when there is none.";
  }
  if (finding.id.startsWith("diff:unscoped:")) {
    return "Filter this query by the column that identifies the caller (for example the owner or tenant id), the same way the sibling routes do.";
  }
  return "Remove the credential from this file, then rotate it with its provider. It stays in git history even after the file changes.";
}

/** The committed file and PR body: a labeled fix request, never presented as a
 * tested code change. Plain copy, no dashes. */
export function pullRequestFixDocument(prNumber: number, finding: ReviewFinding): string {
  return [
    `# ShipLock fix request for pull request #${prNumber}`,
    "",
    `**${finding.title}** (${finding.severity})`,
    "",
    `Where: \`${finding.file}\``,
    "",
    `Why it matters: ${finding.detail}`,
    "",
    `Evidence: ${finding.evidence}`,
    "",
    `What to change: ${instruction(finding)}`,
    "",
    "This is a fix request, not a tested code change. Make the change on your branch (your coding agent can apply it from this file), delete this file, and merge when your checks pass. ShipLock never merges or deploys.",
    "",
  ].join("\n");
}

/**
 * Fix before merge (8B-3): a fix PR into the checked pull request's own head
 * branch, built from the stored review. A fork, a closed or deleted branch, or
 * a finding no longer in the review is refused; there is never a fallback to
 * the default branch. The branch name is deterministic per review and finding,
 * so a retry after an uncertain delivery recovers the same PR.
 */
export async function openPullRequestFixPr(
  userId: string, reviewId: string, findingId: string, repositoryId: string,
): Promise<RepairOutcome> {
  const admin = getSupabaseAdmin();
  const [{ data: rawReview }, { data: profile }] = await Promise.all([
    admin.from("pull_request_reviews")
      .select("pull_request_number, head_ref, same_repository, findings, repositories(full_name)")
      .eq("id", reviewId).eq("user_id", userId).eq("repository_id", repositoryId).maybeSingle(),
    admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle(),
  ]);
  const review = reviewSchema.safeParse(rawReview);
  if (!review.success) return { status: "failed", code: "finding_unavailable" };
  const finding = review.data.findings.find((item) => item.id === findingId);
  if (!finding) return { status: "failed", code: "finding_unavailable" };
  if (review.data.same_repository !== true || !review.data.head_ref) return { status: "failed", code: "fork_pull_request" };
  const installationId = profile?.github_installation_id as number | string | null | undefined;
  if (!installationId) return { status: "failed", code: "repository_unavailable" };

  const repository = review.data.repositories.full_name;
  const headRef = review.data.head_ref;
  const prNumber = review.data.pull_request_number;
  const token = await getInstallationToken(installationId);
  const branch = `shiplock/pr-${prNumber}-fix-${createHash("sha256").update(`${reviewId}\0${findingId}`).digest("hex").slice(0, 12)}`;

  let url = await findOpenPullRequestForBranch(token, repository, branch);
  if (!url) {
    const headSha = await getBranchSha(token, repository, headRef).catch(() => null);
    if (!headSha) return { status: "failed", code: "pull_request_closed" };
    const existing = await getBranchSha(token, repository, branch).then(() => true, () => false);
    if (!existing) await createBranch(token, repository, branch, headSha);
    const document = pullRequestFixDocument(prNumber, finding);
    const path = `.shiplock/fixes/pr-${prNumber}-${createHash("sha256").update(findingId).digest("hex").slice(0, 12)}.md`;
    await putFile(token, repository, path, branch, document, undefined, `ShipLock: fix request for #${prNumber}`);
    url = await openPullRequest(token, repository, branch, headRef,
      `ShipLock fix request for #${prNumber}: ${finding.title}`.slice(0, 250), document);
  }
  return openedOutcome(url);
}

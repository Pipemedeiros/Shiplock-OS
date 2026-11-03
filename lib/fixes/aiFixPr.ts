import { createHash } from "node:crypto";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { createBranch, findOpenPullRequestForBranch, getBranchSha, getFile, getFileSha, getInstallationToken,
  openPullRequest, putFile } from "@/lib/deep/github";
import { mechanicalEdit } from "@/lib/intelligence/tasks";
import { openedOutcome, type RepairOutcome } from "./repairOutcome";

// One click, one PR for a change the customer's own AI proposed. The
// proposal was already checked at submit time; here it is checked again
// against the branch the PR will target: every file must still be exactly what
// the AI read, and every edit must still be an allowlisted mechanical change.
// A PR-scan proposal targets that PR's own branch (fix before merge); anything
// else targets the default branch. ShipLock never merges or deploys.

const taskSchema = z.object({
  id: z.uuid(), repository_id: z.uuid(), status: z.string(), idempotency_key: z.string(), host: z.string(),
  result: z.object({
    summary: z.string(), model: z.string().optional(),
    edits: z.array(z.object({ path: z.string(), baseHash: z.string(), content: z.string() })).min(1).max(3),
  }),
  repositories: z.object({ full_name: z.string(), default_branch: z.string(), selected: z.boolean() }),
});
const JOB_KEY = /^job:([0-9a-f-]{36})$/;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** Model text in a PR body: quoted, with mentions and HTML defused. */
function inert(text: string): string {
  return text.slice(0, 2000).replace(/@/g, "@​").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .split("\n").map((line) => `> ${line}`).join("\n");
}

async function targetBranch(taskKey: string, defaultBranch: string, repositoryId: string, userId: string)
  : Promise<string | Extract<RepairOutcome, { status: "failed" }>> {
  const jobId = JOB_KEY.exec(taskKey)?.[1];
  if (!jobId) return defaultBranch;
  const admin = getSupabaseAdmin();
  const { data: scan, error } = await admin.from("intelligence_scan_jobs")
    .select("scan, pull_request_number, head_sha").eq("job_id", jobId).eq("user_id", userId).maybeSingle();
  if (error) throw new Error("scan context unreadable");
  if (!scan || scan.scan !== "pr") return defaultBranch;
  const { data: review, error: reviewError } = await admin.from("pull_request_reviews")
    .select("head_ref, same_repository").eq("user_id", userId).eq("repository_id", repositoryId)
    .eq("pull_request_number", scan.pull_request_number).eq("head_sha", scan.head_sha).maybeSingle();
  if (reviewError) throw new Error("pull request review unreadable");
  if (!review) return { status: "failed", code: "pull_request_closed" };
  if (review.same_repository !== true || !review.head_ref) return { status: "failed", code: "fork_pull_request" };
  return review.head_ref as string;
}

export async function openAiFixPr(userId: string, taskId: string, repositoryId: string): Promise<RepairOutcome> {
  const admin = getSupabaseAdmin();
  const { data, error } = await admin.from("intelligence_tasks")
    .select("id, repository_id, status, idempotency_key, host, result, repositories(full_name, default_branch, selected)")
    .eq("id", taskId).eq("user_id", userId).maybeSingle();
  if (error) throw new Error("task unreadable");
  const parsed = taskSchema.safeParse(data);
  if (!parsed.success || parsed.data.status !== "proposal_received") return { status: "failed", code: "finding_unavailable" };
  const task = parsed.data;
  if (task.repository_id !== repositoryId || !task.repositories.selected) return { status: "failed", code: "repository_unavailable" };

  const { data: profile } = await admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle();
  if (!profile?.github_installation_id) return { status: "failed", code: "repository_unavailable" };
  const base = await targetBranch(task.idempotency_key, task.repositories.default_branch, repositoryId, userId);
  if (typeof base !== "string") return base;

  const repo = task.repositories.full_name;
  const token = await getInstallationToken(profile.github_installation_id as number);
  const branch = `shiplock/ai-fix-${sha(`${userId}\0${taskId}`).slice(0, 20)}`;
  const recovered = await findOpenPullRequestForBranch(token, repo, branch);
  if (recovered) return openedOutcome(recovered);

  // The target branch must still hold exactly what the AI read, and each edit
  // must still pass the mechanical guard against that content.
  for (const edit of task.result.edits) {
    const current = await getFile(token, repo, edit.path, base);
    if (current === null || sha(current) !== edit.baseHash) return { status: "failed", code: "source_changed" };
    if (!mechanicalEdit({ path: edit.path, content: current }, edit.content)) return { status: "failed", code: "not_fixable" };
  }

  const files = task.result.edits.map((edit) => edit.path);
  const title = `ShipLock: AI-proposed change to ${files.join(", ")}`.slice(0, 200);
  const baseSha = await getBranchSha(token, repo, base);
  const exists = await getBranchSha(token, repo, branch).then(() => true).catch(() => false);
  if (!exists) await createBranch(token, repo, branch, baseSha);
  for (const edit of task.result.edits) {
    const existingSha = await getFileSha(token, repo, edit.path, branch);
    const existing = existingSha ? await getFile(token, repo, edit.path, branch).catch(() => null) : null;
    if (existing !== edit.content) await putFile(token, repo, edit.path, branch, edit.content, existingSha ?? undefined, title);
  }
  const body = [
    `Proposed by your own AI (${task.host}${task.result.model ? `, ${task.result.model}` : ""}) and opened after your click in ShipLock.`,
    "", "What your AI said:", "", inert(task.result.summary), "",
    "ShipLock checked every citation against GitHub and allowed only an allowlisted mechanical change. "
      + "Tests were not run by ShipLock: let your CI run and review the diff before merging.",
    "", "ShipLock never merges or deploys. Merging is your decision.",
  ].join("\n");
  return openedOutcome(await openPullRequest(token, repo, branch, base, title, body));
}

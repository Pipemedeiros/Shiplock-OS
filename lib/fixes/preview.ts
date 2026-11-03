import { capturePreview, getFile } from "@/lib/deep/github";
import { openRiskFixPr } from "./riskFixPr";
import { openFindingFixPr } from "./findingFixPr";
import { openDependencyBumpPr } from "@/lib/deep/githubFixRun";
import { openPullRequestFixPr } from "./pullRequestFixPr";
import { openAiFixPr } from "./aiFixPr";
import { openRateLimitPr } from "./rateLimitPr";
import type { RepairOutcome } from "./repairOutcome";
import { stampedFixName } from "./content";

/**
 * One preview for every repair lane. It runs the lane's real
 * code inside capturePreview, so GitHub writes are recorded instead of sent
 * and the lane stops at "open pull request": the preview is exactly what the
 * click would write, and nothing is written. The click itself still goes
 * through the receipted repair job. The installation token never leaves this
 * module.
 */
export type RepairAction = "risk-fix-pr" | "finding-fix-pr" | "dependency-bump-pr" | "pr-fix-pr" | "ai-fix-pr" | "rate-limit-pr";
export type RepairPreviewRequest = {
  action: RepairAction; repositoryId: string;
  findingId?: string; editedContent?: string | null; reviewId?: string; taskId?: string;
};
export type RepairPreview =
  | { status: "planned"; lane: string; repository: string; base: string; branch: string; title: string; body: string;
      tests: "not run by ShipLock"; files: { path: string; change: "add" | "edit"; before: string | null; after: string; nameSetAtClick?: true }[] }
  | { status: "already_open"; url: string }
  | { status: "unavailable"; code: string };

const LANE_NAMES: Record<RepairAction, string> = {
  "risk-fix-pr": "Fix", "finding-fix-pr": "Fix", "dependency-bump-pr": "Dependency update",
  "pr-fix-pr": "Fix before merge", "ai-fix-pr": "Your AI's fix", "rate-limit-pr": "Rate limit",
};

// The same dispatch as lib/jobs/repairWorker.ts. Not exported: it is only ever
// called inside capturePreview below (pinned by lib/security/prWrites.test.ts).
function runLane(userId: string, r: RepairPreviewRequest): Promise<RepairOutcome> {
  switch (r.action) {
    case "risk-fix-pr": return openRiskFixPr(userId, r.findingId!, r.repositoryId);
    case "finding-fix-pr": return openFindingFixPr(userId, r.findingId!, r.editedContent ?? null, r.repositoryId);
    case "pr-fix-pr": return openPullRequestFixPr(userId, r.reviewId!, r.findingId!, r.repositoryId);
    case "ai-fix-pr": return openAiFixPr(userId, r.taskId!, r.repositoryId);
    case "rate-limit-pr": return openRateLimitPr(userId, r.findingId!, r.repositoryId);
    case "dependency-bump-pr": return openDependencyBumpPr(userId, r.repositoryId);
  }
}

/** What a fix click would write, before the click: each file as it is today and
 * as the pull request would leave it. */
export async function previewRepair(userId: string, request: RepairPreviewRequest): Promise<RepairPreview> {
  const capture = await capturePreview(() => runLane(userId, request));
  if (capture.status === "already_open") return { status: "already_open", url: capture.url };
  if (capture.status === "not_planned") {
    const result = capture.result as RepairOutcome | undefined;
    return { status: "unavailable", code: result && result.status === "failed" ? result.code : "not_planned" };
  }
  // What each file holds today on the branch the PR targets.
  const files = await Promise.all(capture.files.map(async (file) => {
    const before = await getFile(capture.token, capture.repository, file.path, capture.base).catch(() => null);
    const change = before === null ? "add" as const : "edit" as const;
    // A new ShipLock fix file is named with the click's timestamp, not the preview's.
    return { path: file.path, change, before, after: file.content, ...(change === "add" && stampedFixName(file.path) ? { nameSetAtClick: true as const } : {}) };
  }));
  return { status: "planned", lane: LANE_NAMES[request.action], repository: capture.repository, base: capture.base,
    branch: capture.branch, title: capture.title, body: capture.body, tests: "not run by ShipLock", files };
}

import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { openRiskFixPr } from "@/lib/fixes/riskFixPr";
import { openFindingFixPr } from "@/lib/fixes/findingFixPr";
import { openDependencyBumpPr } from "@/lib/deep/githubFixRun";
import { openPullRequestFixPr } from "@/lib/fixes/pullRequestFixPr";
import { openAiFixPr } from "@/lib/fixes/aiFixPr";
import { openRateLimitPr } from "@/lib/fixes/rateLimitPr";
import type { RepairOutcome } from "@/lib/fixes/repairOutcome";
import { claimJob, executeClaimedJob, PermanentJobError, withLeaseHeartbeat, type ClaimedJob } from "./queue";

const receiptSchema = z.object({
  user_id: z.uuid(), repository_id: z.uuid(),
  action: z.enum(["risk-fix-pr", "finding-fix-pr", "dependency-bump-pr", "pr-fix-pr", "ai-fix-pr", "rate-limit-pr"]),
  review_id: z.uuid().nullable(),
  task_id: z.uuid().nullable(),
  finding_id: z.string().min(1).max(400).nullable(),
  edited_content: z.string().max(60_000).nullable(),
  status: z.enum(["queued", "opened", "failed", "uncertain"]),
});

/**
 * One customer click, one PR. The route only admitted a receipt; this
 * worker re-resolves the finding, opens the PR under the job's lease, and
 * records the outcome on the receipt. A GitHub error that might have happened
 * after the PR was created is recorded as `uncertain` and retried; the
 * deterministic branch lets the retry recover the PR instead of duplicating
 * it. ShipLock never merges or deploys.
 */
export async function executeRepairJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "repair" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid repair context");
  }
  const admin = getSupabaseAdmin();
  const { data, error } = await admin.from("repair_action_receipts")
    .select("user_id, repository_id, action, finding_id, edited_content, review_id, task_id, status")
    .eq("job_id", job.id).maybeSingle();
  if (error) throw new Error("Repair receipt could not be read");
  const receipt = receiptSchema.safeParse(data);
  if (!receipt.success || receipt.data.user_id !== job.user_id || receipt.data.repository_id !== job.repository_id) {
    throw new PermanentJobError("Repair receipt changed");
  }
  if (receipt.data.status === "opened" || receipt.data.status === "failed") return;

  const record = async (outcome: RepairOutcome | { status: "uncertain" }) => {
    const { data: recorded, error: recordError } = await admin.rpc("complete_repair_action", {
      p_user: job.user_id, p_job: job.id, p_token: job.lease_token, p_status: outcome.status,
      p_url: outcome.status === "opened" ? outcome.url : null,
      p_number: outcome.status === "opened" ? outcome.number : null,
      p_failure: outcome.status === "opened" ? null
        : outcome.status === "uncertain" ? "delivery_unconfirmed" : outcome.code,
    });
    if (recordError || recorded !== true) throw new Error("Repair receipt could not be recorded");
  };

  const { action, finding_id: findingId, edited_content: edited, review_id: reviewId, task_id: taskId } = receipt.data;
  await withLeaseHeartbeat(job, async () => {
    let outcome: RepairOutcome;
    try {
      outcome = action === "risk-fix-pr" ? await openRiskFixPr(job.user_id, findingId!, job.repository_id!)
        : action === "finding-fix-pr" ? await openFindingFixPr(job.user_id, findingId!, edited, job.repository_id!)
        : action === "pr-fix-pr" ? await openPullRequestFixPr(job.user_id, reviewId!, findingId!, job.repository_id!)
        : action === "ai-fix-pr" ? await openAiFixPr(job.user_id, taskId!, job.repository_id!)
        : action === "rate-limit-pr" ? await openRateLimitPr(job.user_id, findingId!, job.repository_id!)
        : await openDependencyBumpPr(job.user_id, job.repository_id!);
    } catch (err) {
      await record({ status: "uncertain" }).catch(() => {});
      throw err;
    }
    await record(outcome);
  });
}

/** Claims and runs one clicked repair; false when the queue had none. */
export async function runNextRepairJob(): Promise<boolean> {
  const job = await claimJob("repair");
  if (!job) return false;
  await executeClaimedJob(job, [executeRepairJob]);
  return true;
}

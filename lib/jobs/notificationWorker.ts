import { z } from "zod";
import { sendNewFindingsAlert } from "@/lib/monitoring/alerts";
import { sendPullRequestAlert } from "@/lib/monitoring/pullRequestAlert";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  claimJob,
  executeClaimedJob,
  PermanentJobError,
  withLeaseHeartbeat,
  type ClaimedJob,
} from "./queue";

const finding = z.object({
  id: z.string().min(1).max(1_000),
  severity: z.enum(["CRITICAL", "WARNING", "INFO"]),
  title: z.string().min(1).max(1_000),
  consequence: z.string().min(1).max(20_000),
});
const batchSchema = z.object({
  user_id: z.uuid(),
  findings: z.array(finding).min(1).max(100),
});
const pullRequestSchema = z.object({
  user_id: z.uuid(),
  pull_request_reviews: z.object({
    user_id: z.uuid(), pull_request_number: z.number().int().positive(), title: z.string().nullable(),
    verdict: z.enum(["pass", "warn", "block"]),
    findings: z.array(z.object({ severity: z.enum(["CRITICAL", "WARNING"]), title: z.string(), file: z.string() })),
    repositories: z.object({ full_name: z.string() }),
  }),
});
const profileSchema = z.object({ email: z.string().email().nullable(), is_paid: z.boolean().nullable().optional() });

/** Email is an at-least-once side effect and paid only (AGENTS.md): a free
 * account's alert job completes without sending. alerts.ts records dedup only
 * after a confirmed send, so an uncertain acknowledgement prefers a duplicate
 * over seven days of silence about a critical finding. */
export async function executeNotificationJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "notification" || job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid notification context");
  }
  const admin = getSupabaseAdmin();
  const [batchRead, pullRequestRead, profileRead] = await Promise.all([
    admin
      .from("monitoring_notification_batches")
      .select("user_id, findings")
      .eq("job_id", job.id)
      .maybeSingle(),
    admin
      .from("pull_request_notifications")
      .select("user_id, pull_request_reviews(user_id, pull_request_number, title, verdict, findings, repositories(full_name))")
      .eq("job_id", job.id)
      .maybeSingle(),
    admin.from("user_profiles").select("email, is_paid").eq("id", job.user_id).maybeSingle(),
  ]);
  if (batchRead.error || pullRequestRead.error || profileRead.error) {
    throw new Error("Notification context could not be read");
  }
  const profile = profileSchema.safeParse(profileRead.data);
  if (!profile.success) throw new PermanentJobError("Notification context changed");
  const paid = profile.data.is_paid === true;
  const email = profile.data.email;

  if (batchRead.data) {
    const batch = batchSchema.safeParse(batchRead.data);
    if (!batch.success || batch.data.user_id !== job.user_id) throw new PermanentJobError("Notification context changed");
    if (!email || !paid) return;
    const delivery = await withLeaseHeartbeat(job, () => sendNewFindingsAlert(job.user_id, email, batch.data.findings));
    if (delivery === "failed") throw new Error("Notification delivery failed");
    return;
  }

  const pullRequest = pullRequestSchema.safeParse(pullRequestRead.data);
  if (!pullRequest.success || pullRequest.data.user_id !== job.user_id
    || pullRequest.data.pull_request_reviews.user_id !== job.user_id) {
    throw new PermanentJobError("Notification context changed");
  }
  const review = pullRequest.data.pull_request_reviews;
  // A re-check of the same head that no longer blocks owes no alert.
  if (!email || !paid || review.verdict !== "block" || review.findings.length === 0) return;
  const delivery = await withLeaseHeartbeat(job, () => sendPullRequestAlert(email, {
    repository: review.repositories.full_name, number: review.pull_request_number, title: review.title,
    findings: review.findings.map(({ severity, title, file }) => ({ severity, title, file })),
  }));
  if (delivery === "failed") throw new Error("Notification delivery failed");
}

/** Claims and runs one notification job; false when the queue had none. */
export async function runNextNotificationJob(): Promise<boolean> {
  const job = await claimJob("notification");
  if (!job) return false;
  await executeClaimedJob(job, [executeNotificationJob]);
  return true;
}

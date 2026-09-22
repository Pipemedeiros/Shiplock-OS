import { z } from "zod";
import { sendNewFindingsAlert } from "@/lib/monitoring/alerts";
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
const profileSchema = z.object({ email: z.string().email().nullable() });

/** Email is an at-least-once side effect. alerts.ts records dedup only after a
 * confirmed send, so an uncertain acknowledgement prefers a duplicate over
 * seven days of silence about a critical finding. */
export async function executeNotificationJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "notification" || job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid notification context");
  }
  const admin = getSupabaseAdmin();
  const [batchRead, profileRead] = await Promise.all([
    admin
      .from("monitoring_notification_batches")
      .select("user_id, findings")
      .eq("job_id", job.id)
      .maybeSingle(),
    admin.from("user_profiles").select("email").eq("id", job.user_id).maybeSingle(),
  ]);
  if (batchRead.error || profileRead.error) {
    throw new Error("Notification context could not be read");
  }
  const batch = batchSchema.safeParse(batchRead.data);
  const profile = profileSchema.safeParse(profileRead.data);
  if (!batch.success || batch.data.user_id !== job.user_id || !profile.success) {
    throw new PermanentJobError("Notification context changed");
  }
  if (!profile.data.email) return;
  const delivery = await withLeaseHeartbeat(job, () =>
    sendNewFindingsAlert(job.user_id, profile.data.email!, batch.data.findings),
  );
  if (delivery === "failed") throw new Error("Notification delivery failed");
}

export async function runNextNotificationJob(): Promise<boolean> {
  const job = await claimJob("notification");
  if (!job) return false;
  await executeClaimedJob(job, [executeNotificationJob]);
  return true;
}

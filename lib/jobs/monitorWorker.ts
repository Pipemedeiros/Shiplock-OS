import { z } from "zod";
import { runMonitoringPassForWorker } from "@/lib/monitoring/run";
import { fencedProviderCommit } from "@/lib/monitoring/providerCommit";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  claimJob,
  executeClaimedJob,
  PermanentJobError,
  withLeaseHeartbeat,
  type ClaimedJob,
} from "./queue";

const trigger = z.enum(["manual", "deploy", "hourly", "scheduled_48h"]);
const contextSchema = z.object({ user_id: z.uuid(), trigger_source: trigger });
const profileSchema = z.object({
  id: z.uuid(),
  monitoring_enabled: z.boolean(),
  monitored_project_url: z.string().min(1).nullable(),
  monitored_anon_key_encrypted: z.string().min(1).nullable(),
  monitored_app_url: z.string().min(1).nullable(),
  postgres_dsn_encrypted: z.string().min(1).nullable(),
  vercel_access_token_encrypted: z.string().min(1).nullable(),
  vercel_connection_epoch: z.string().nullable(),
  supabase_endpoint_connection_epoch: z.string().nullable(),
  vercel_team_id: z.string().nullable(),
  supabase_mgmt_token_encrypted: z.string().min(1).nullable(),
  supabase_mgmt_project_ref: z.string().min(1).nullable(),
}).refine((value) => Boolean(
  (value.monitoring_enabled && value.monitored_project_url && value.monitored_anon_key_encrypted)
  || (value.monitoring_enabled && value.monitored_app_url)
  || value.postgres_dsn_encrypted
  || value.vercel_access_token_encrypted
  || (value.supabase_mgmt_token_encrypted && value.supabase_mgmt_project_ref)
));

function notificationBatch(
  jobId: string,
  findings: Awaited<ReturnType<typeof runMonitoringPassForWorker>>["newFindings"],
) {
  const maxBytes = 240 * 1024;
  if (findings.length <= 100 && Buffer.byteLength(JSON.stringify(findings), "utf8") <= maxBytes) {
    return findings;
  }
  const priority = { CRITICAL: 0, WARNING: 1, INFO: 2 } as const;
  const ordered = findings
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => priority[a.finding.severity] - priority[b.finding.severity] || a.index - b.index)
    .map(({ finding }) => finding);
  const selected: typeof findings = [];
  for (const finding of ordered) {
    if (selected.length === 99) break;
    if (Buffer.byteLength(JSON.stringify([...selected, finding]), "utf8") <= maxBytes - 2_048) {
      selected.push(finding);
    }
  }
  const summary = {
      id: `monitoring:additional-findings:${jobId}`,
      severity: "INFO" as const,
      title: `${findings.length - selected.length} additional new findings are in ShipLock`,
      consequence: "Open the dashboard to review the complete evidence set.",
  };
  return [...selected, summary];
}

/** Run one current provider-monitoring context. The queue stores no credential;
 * disconnecting every applicable provider turns the job into a permanent no-op. */
export async function executeMonitorJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "monitor" || job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid monitoring context");
  }
  const admin = getSupabaseAdmin();
  const [contextRead, profileRead] = await Promise.all([
    admin.from("monitoring_job_context").select("user_id, trigger_source").eq("job_id", job.id).maybeSingle(),
    admin.from("user_profiles").select(
      "id, monitoring_enabled, monitored_project_url, monitored_anon_key_encrypted, monitored_app_url, postgres_dsn_encrypted, vercel_access_token_encrypted, vercel_connection_epoch, supabase_endpoint_connection_epoch, vercel_team_id, supabase_mgmt_token_encrypted, supabase_mgmt_project_ref",
    ).eq("id", job.user_id).maybeSingle(),
  ]);
  if (contextRead.error || profileRead.error) throw new Error("Monitoring context could not be read");
  const context = contextSchema.safeParse(contextRead.data);
  const profile = profileSchema.safeParse(profileRead.data);
  if (!context.success || context.data.user_id !== job.user_id || !profile.success) {
    throw new PermanentJobError("Monitoring context changed");
  }
  if (context.data.trigger_source === "hourly"
    && (!profile.data.monitoring_enabled || !profile.data.monitored_project_url || !profile.data.monitored_anon_key_encrypted)) {
    throw new PermanentJobError("Hourly monitoring context changed");
  }

  await withLeaseHeartbeat(job, async () => {
    try {
      const result = await runMonitoringPassForWorker(
        { ...profile.data, email: null },
        context.data.trigger_source,
        undefined,
        fencedProviderCommit(job.user_id, job.id, job.lease_token),
      );
      const { error } = await admin.rpc("enqueue_monitoring_notifications", {
        p_user: job.user_id,
        p_source_job: job.id,
        p_token: job.lease_token,
        p_findings: notificationBatch(job.id, result.newFindings),
      });
      if (error) throw new Error("Monitoring notifications could not be queued");
      // Admit alerts before retrying a failed coverage/cursor write. Provider
      // collectors self-diff today; on retry, a just-inserted finding is no
      // longer "new", so throwing before this point could silence its alert.
      if (!result.writesSucceeded) {
        throw new Error("Monitoring coverage could not be stored");
      }
    } finally {
      if (context.data.trigger_source === "hourly") {
        const { data, error } = await admin.rpc("stamp_hourly_monitor_attempt", {
          p_user: job.user_id,
          p_job: job.id,
          p_token: job.lease_token,
        });
        if (error || data !== true) throw new Error("Hourly monitoring receipt could not be saved");
      }
    }
  });
}

export async function runNextMonitorJob(): Promise<boolean> {
  const job = await claimJob("monitor");
  if (!job) return false;
  await executeClaimedJob(job, [executeMonitorJob]);
  return true;
}

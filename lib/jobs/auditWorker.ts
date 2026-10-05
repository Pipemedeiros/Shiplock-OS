import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runRepositoryAudit } from "@/lib/agent/audit";
import { AuditTrigger, claimJob, executeClaimedJob, PermanentJobError, type ClaimedJob } from "./queue";

const profileSchema = z.object({
  github_installation_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  supabase_mgmt_token_encrypted: z.unknown().nullable().optional(),
  postgres_dsn_encrypted: z.unknown().nullable().optional(),
});
const repositorySchema = z.object({ full_name: z.string().regex(/^[\w.-]+\/[\w.-]+$/), selected: z.literal(true),
  default_branch: z.string().min(1) });
const runSchema = z.object({
  status: z.enum(["queued", "running", "complete", "failed"]),
  full_name: z.string(),
  trigger: AuditTrigger,
});

/** Execute one claimed audit from current tenant-owned context. The job stores
 * identities only; credentials and repository state are re-read at execution. */
export async function executeAuditJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "audit" || !job.repository_id || !job.audit_run_id) throw new PermanentJobError("Invalid audit context");
  const admin = getSupabaseAdmin();
  const [profileRead, repositoryRead, runRead] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id, supabase_mgmt_token_encrypted, postgres_dsn_encrypted")
      .eq("id", job.user_id).maybeSingle(),
    admin.from("repositories").select("full_name, selected, default_branch").eq("id", job.repository_id)
      .eq("user_id", job.user_id).maybeSingle(),
    admin.from("audit_runs").select("status, full_name, trigger").eq("id", job.audit_run_id)
      .eq("user_id", job.user_id).eq("repository_id", job.repository_id).maybeSingle(),
  ]);
  if (profileRead.error || repositoryRead.error || runRead.error) throw new Error("Audit context could not be read");
  const profile = profileSchema.safeParse(profileRead.data);
  const repository = repositorySchema.safeParse(repositoryRead.data);
  const run = runSchema.safeParse(runRead.data);
  if (!profile.success || !repository.success || !run.success || run.data.full_name !== repository.data.full_name) {
    throw new PermanentJobError("Audit context changed");
  }
  // A lost completion acknowledgement may cause a retry after the audit itself
  // committed. The completed run is the durable result; never run it twice.
  if (run.data.status === "complete") return;
  await runRepositoryAudit({
    userId: job.user_id,
    installationId: profile.data.github_installation_id,
    repositoryId: job.repository_id,
    fullName: repository.data.full_name,
    defaultBranch: repository.data.default_branch,
    trigger: run.data.trigger,
    hasDatabase: Boolean(profile.data.supabase_mgmt_token_encrypted || profile.data.postgres_dsn_encrypted),
    runId: job.audit_run_id,
    jobLease: { jobId: job.id, token: job.lease_token },
  });
}

/** Claim at most one audit. Concurrent callers are bounded and tenant-fair in
 * SQL; this function does no polling and is safe to call after a 202 response. */
export async function runNextAuditJob(): Promise<boolean> {
  const job = await claimJob("audit");
  if (!job) return false;
  await executeClaimedJob(job, [executeAuditJob]);
  return true;
}

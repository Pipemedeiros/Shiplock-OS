import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runPullRequestCheck } from "@/lib/agent/prCheck";
import { claimJob, executeClaimedJob, PermanentJobError, type ClaimedJob } from "./queue";

const profileSchema = z.object({ github_installation_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER) });
const repositorySchema = z.object({ full_name: z.string().regex(/^[\w.-]+\/[\w.-]+$/), selected: z.literal(true) });
const contextSchema = z.object({
  user_id: z.uuid(), repository_id: z.uuid(), pull_request_number: z.number().int().positive(),
  head_sha: z.string().regex(/^[a-f0-9]{7,64}$/),
});

/** Execute a PR check from identity-only durable context. Credentials and the
 * selected repository are re-read so disconnect/reselection revokes work. */
export async function executePullRequestCheckJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "pr-check" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid pull request check context");
  }
  const admin = getSupabaseAdmin();
  const [profileRead, repositoryRead, contextRead] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id").eq("id", job.user_id).maybeSingle(),
    admin.from("repositories").select("full_name, selected").eq("id", job.repository_id).eq("user_id", job.user_id).maybeSingle(),
    admin.from("pull_request_jobs").select("user_id, repository_id, pull_request_number, head_sha").eq("job_id", job.id).maybeSingle(),
  ]);
  if (profileRead.error || repositoryRead.error || contextRead.error) throw new Error("Pull request check context could not be read");
  const profile = profileSchema.safeParse(profileRead.data);
  const repository = repositorySchema.safeParse(repositoryRead.data);
  const context = contextSchema.safeParse(contextRead.data);
  if (!profile.success || !repository.success || !context.success
    || context.data.user_id !== job.user_id || context.data.repository_id !== job.repository_id) {
    throw new PermanentJobError("Pull request check context changed");
  }
  await runPullRequestCheck({
    userId: job.user_id,
    installationId: profile.data.github_installation_id,
    fullName: repository.data.full_name,
    prNumber: context.data.pull_request_number,
    headSha: context.data.head_sha,
    // Fenced to this job's lease and exact PR head (migration 071).
    persistReview: async (review) => {
      const { error } = await admin.rpc("persist_pull_request_review", {
        p_user: job.user_id, p_job: job.id, p_token: job.lease_token, p_review: review,
      });
      if (error) throw new Error("Pull request review could not be stored");
    },
  });
}

/** Claims and runs one pull request check; false when the queue had none. */
export async function runNextPullRequestCheckJob(): Promise<boolean> {
  const job = await claimJob("pr-check");
  if (!job) return false;
  await executeClaimedJob(job, [executePullRequestCheckJob]);
  return true;
}

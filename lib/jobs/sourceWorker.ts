import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { collectRepositorySource } from "@/lib/deep/githubRun";
import { getInstallationToken, listRepos } from "@/lib/deep/github";
import {
  claimJob,
  enqueueJob,
  executeClaimedJob,
  PermanentJobError,
  withLeaseHeartbeat,
  type ClaimedJob,
} from "./queue";

const providerRepositoryId = z.union([
  z.string().regex(/^[1-9]\d*$/),
  z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
]).transform(String).nullable();
const profileSchema = z.object({
  github_installation_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
const repositorySchema = z.object({
  full_name: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  github_repo_id: providerRepositoryId,
  default_branch: z.string().min(1).max(255),
  selected: z.literal(true),
});
const resultSchema = z.object({
  total: z.number().int().nonnegative(),
  newCount: z.number().int().nonnegative(),
  resolvedCount: z.literal(0),
});

function findingPayload(findings: Awaited<ReturnType<typeof collectRepositorySource>>["findings"]) {
  return findings.map((finding) => ({
    finding_id: finding.id,
    severity: finding.severity,
    title: finding.title,
    consequence: finding.consequence,
    package_name: finding.packageName,
    version: finding.version,
    vuln_id: finding.vulnId,
    cve_id: finding.cveId,
  }));
}

/** Collect one current selected repository, then atomically persist only while
 * this attempt owns the live source-job lease. */
export async function executeSourceJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "source" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid source context");
  }
  const repositoryId = job.repository_id;
  const admin = getSupabaseAdmin();
  const [profileRead, repositoryRead] = await Promise.all([
    admin.from("user_profiles").select("github_installation_id")
      .eq("id", job.user_id).maybeSingle(),
    admin.from("repositories").select("full_name, github_repo_id, default_branch, selected")
      .eq("id", repositoryId).eq("user_id", job.user_id).maybeSingle(),
  ]);
  if (profileRead.error || repositoryRead.error) throw new Error("Source context could not be read");
  const profile = profileSchema.safeParse(profileRead.data);
  const repository = repositorySchema.safeParse(repositoryRead.data);
  if (!profile.success || !repository.success) throw new PermanentJobError("Source context changed");

  await withLeaseHeartbeat(job, async () => {
    const token = await getInstallationToken(profile.data.github_installation_id);
    const visible = (await listRepos(token)).find((candidate) => repository.data.github_repo_id
      ? candidate.id === repository.data.github_repo_id
      : candidate.fullName === repository.data.full_name);
    if (!visible || visible.fullName !== repository.data.full_name
        || visible.defaultBranch !== repository.data.default_branch) {
      throw new PermanentJobError("Source repository identity changed");
    }
    const collected = await collectRepositorySource(
      token,
      visible,
      repositoryId,
      profile.data.github_installation_id,
    );
    const { data, error } = await admin.rpc("persist_repository_source", {
      p_user: job.user_id,
      p_repository: repositoryId,
      p_job: job.id,
      p_token: job.lease_token,
      p_snapshot: collected.snapshot,
      p_findings: findingPayload(collected.findings),
    });
    if (error) throw new Error("Source evidence could not be saved");
    resultSchema.parse(data);
  });
}

/** Downstream jobs are separate retry/fencing domains. Keys bind manual and
 * webhook follow-ups to this source attempt; scheduled dependency work shares
 * the repository/day key so concurrent schedulers remain idempotent. */
export async function enqueueFollowUpsAfterSource(job: ClaimedJob): Promise<void> {
  if (job.kind !== "source" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid source follow-up context");
  }
  const scheduled = /^scheduled-source:([0-9a-f-]{36}):(\d{4}-\d{2}-\d{2})$/i.exec(
    job.deduplication_key,
  );
  const dependencyKey = scheduled?.[1]?.toLowerCase() === job.repository_id.toLowerCase()
    ? `scheduled-dependency:${job.repository_id}:${scheduled[2]}`
    : `dependency-after-source:${job.id}`;
  await enqueueJob(job.user_id, job.repository_id, "dependency", dependencyKey);
  await enqueueJob(job.user_id, job.repository_id, "graph", `graph-after-source:${job.id}`);
}

export async function runNextSourceJob(): Promise<boolean> {
  const job = await claimJob("source");
  if (!job) return false;
  await executeClaimedJob(job, [executeSourceJob, enqueueFollowUpsAfterSource]);
  return true;
}

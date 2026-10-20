import { z } from "zod";
import { loadRepositoryDependencies } from "@/lib/graph/repositorySource";
import { collectDependencyFindings } from "@/lib/runtime/zeroDay";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  claimJob,
  executeClaimedJob,
  PermanentJobError,
  withLeaseHeartbeat,
  type ClaimedJob,
} from "./queue";

const resultSchema = z.object({
  total: z.number().int().nonnegative(),
  newCount: z.number().int().nonnegative(),
  resolvedCount: z.number().int().nonnegative(),
});

function payload(findings: Awaited<ReturnType<typeof collectDependencyFindings>>) {
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

async function inventoryFor(job: ClaimedJob) {
  return (await loadRepositoryDependencies(job.user_id))
    .find((inventory) => inventory.repositoryId === job.repository_id);
}

/** Recheck one current repository inventory. OSV is read-only; the result can
 * commit only if both the job lease and source observation remain current. */
export async function executeDependencyJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "dependency" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid dependency context");
  }
  const inventory = await inventoryFor(job);
  if (!inventory) throw new PermanentJobError("Dependency context changed");
  if (inventory.dependencies.length === 0) return;

  await withLeaseHeartbeat(job, async () => {
    const findings = await collectDependencyFindings(inventory);
    const current = await inventoryFor(job);
    if (!current || current.sourceRevision !== inventory.sourceRevision) {
      throw new Error("Dependency source evidence changed during collection");
    }
    const { data, error } = await getSupabaseAdmin().rpc(
      "persist_repository_dependency_findings",
      {
        p_user: job.user_id,
        p_repository: job.repository_id,
        p_job: job.id,
        p_token: job.lease_token,
        p_source_revision: inventory.sourceRevision,
        p_findings: payload(findings),
      },
    );
    if (error) throw new Error("Dependency findings could not be saved");
    resultSchema.parse(data);
  });
}

export async function runNextDependencyJob(): Promise<boolean> {
  const job = await claimJob("dependency");
  if (!job) return false;
  await executeClaimedJob(job, [executeDependencyJob]);
  return true;
}

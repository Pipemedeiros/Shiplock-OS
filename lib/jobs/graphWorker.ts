import { z } from "zod";
import { findAttackPaths } from "@/lib/graph/attackPaths";
import { canRetireGraphFindings, loadGraphInput } from "@/lib/graph/graphRun";
import { loadSelectedRepositorySources } from "@/lib/graph/repositorySource";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  claimJob,
  executeClaimedJob,
  PermanentJobError,
  StaleJobError,
  type ClaimedJob,
} from "./queue";

const repositorySchema = z.object({ selected: z.literal(true) });
const resultSchema = z.object({
  total: z.number().int().nonnegative(),
  newCount: z.number().int().nonnegative(),
  resolvedCount: z.number().int().nonnegative(),
});

/** Correlate current, admitted evidence for one repository. The path engine is
 * deterministic; prose generation is deliberately not a prerequisite for this
 * durable security result. SQL owns the fenced multi-row commit. */
export async function executeGraphJob(job: ClaimedJob): Promise<void> {
  if (job.kind !== "graph" || !job.repository_id || job.audit_run_id) {
    throw new PermanentJobError("Invalid graph context");
  }

  const admin = getSupabaseAdmin();
  const repositoryRead = await admin
    .from("repositories")
    .select("selected")
    .eq("id", job.repository_id)
    .eq("user_id", job.user_id)
    .maybeSingle();
  if (repositoryRead.error) throw new Error("Graph context could not be read");
  if (!repositoryRead.data || repositoryRead.data.selected === false) throw new StaleJobError("Repository no longer selected");
  if (!repositorySchema.safeParse(repositoryRead.data).success) {
    throw new PermanentJobError("Graph context changed");
  }

  const before = (await loadSelectedRepositorySources(job.user_id)).get(job.repository_id);
  const input = await loadGraphInput(job.user_id, job.repository_id);
  if (input.repositoryId !== job.repository_id) {
    throw new PermanentJobError("Graph evidence scope changed");
  }
  if (input.sourceCoverage === "unknown") return;
  const after = (await loadSelectedRepositorySources(job.user_id)).get(job.repository_id);
  if (!before || !after || before.snapshot.recordedAt !== after.snapshot.recordedAt) {
    throw new Error("Graph source evidence changed during correlation");
  }
  const findings = findAttackPaths(input).map((path) => ({
    finding_id: path.id,
    severity: path.severity,
    title: path.title,
    consequence: path.consequence,
    surfaces: [...new Set(path.surfaces)],
  }));
  const { data, error } = await admin.rpc("persist_repository_graph", {
    p_user: job.user_id,
    p_repository: job.repository_id,
    p_job: job.id,
    p_token: job.lease_token,
    p_source_revision: after.snapshot.recordedAt,
    p_findings: findings,
    p_allow_retire: canRetireGraphFindings(input),
  });
  if (error) throw new Error("Graph evidence could not be saved");
  resultSchema.parse(data);
}

export async function runNextGraphJob(): Promise<boolean> {
  const job = await claimJob("graph");
  if (!job) return false;
  await executeClaimedJob(job, [executeGraphJob]);
  return true;
}

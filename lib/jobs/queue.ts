import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

export const JobKind = z.enum(["audit", "source", "monitor", "dependency", "graph", "pr-check"]);
export type JobKind = z.infer<typeof JobKind>;
const claimed = z.object({ id: z.uuid(), user_id: z.uuid(), repository_id: z.uuid().nullable(), kind: JobKind,
  audit_run_id: z.uuid().nullable(),
  status: z.literal("running"), attempts: z.number().int().min(1).max(5), lease_token: z.uuid(),
  lease_until: z.string().refine((value) => Number.isFinite(Date.parse(value))), checkpoint: z.number().int().nonnegative(),
});
export type ClaimedJob = z.infer<typeof claimed>;
export type JobOutcome = "heartbeat" | "checkpoint" | "succeeded" | "retry" | "dead" | "cancelled";

/** Stored context no longer authorizes the work; retries cannot repair it. */
export class PermanentJobError extends Error {}

const auditReceipt = z.object({ job_id: z.uuid(), run_id: z.uuid() });

export async function enqueueAuditJob(userId: string, repositoryId: string, key: string) {
  z.uuid().parse(userId); z.uuid().parse(repositoryId); z.string().min(1).max(256).parse(key);
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_repository_audit", {
    p_user: userId, p_repository: repositoryId, p_key: key,
  });
  if (error) throw new Error("Audit could not be queued");
  return auditReceipt.parse(z.array(auditReceipt).length(1).parse(data)[0]);
}

export async function enqueueJob(userId: string, repositoryId: string | null, kind: JobKind, key: string): Promise<string> {
  z.uuid().parse(userId); z.uuid().nullable().parse(repositoryId); JobKind.parse(kind); z.string().min(1).max(256).parse(key);
  if (kind === "audit") throw new Error("Use enqueueAuditJob for audit work");
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_execution_job", {
    p_user: userId, p_repository: repositoryId, p_kind: kind, p_key: key,
  });
  if (error) throw new Error("Work could not be queued");
  return z.uuid().parse(data);
}

export async function claimJob(kind: JobKind): Promise<ClaimedJob | null> {
  JobKind.parse(kind);
  const { data, error } = await getSupabaseAdmin().rpc("claim_execution_job", { p_kind: kind, p_lease_seconds: 120 });
  if (error) throw new Error("Work could not be claimed");
  const jobs = z.array(claimed).max(1).parse(data);
  const job = jobs[0];
  if (job && (job.kind !== kind || Date.parse(job.lease_until) <= Date.now())) throw new Error("Invalid work lease");
  return job ?? null;
}

export async function advanceJob(job: ClaimedJob, checkpoint: number, outcome: JobOutcome): Promise<void> {
  const { data, error } = await getSupabaseAdmin().rpc("advance_execution_job", {
    p_id: job.id, p_token: job.lease_token, p_checkpoint: checkpoint, p_outcome: outcome,
  });
  if (error || data !== true) throw new Error("Work lease lost or transition unavailable");
}

/** A worker supplies restartable stages. Each stage must fence its own writes
 * with the lease token: the queue checkpoint alone cannot make side effects
 * exactly-once. No provider work is registered implicitly here. */
export async function executeClaimedJob(job: ClaimedJob, stages: readonly ((job: ClaimedJob) => Promise<void>)[]) {
  if (job.checkpoint > stages.length) throw new Error("Invalid work checkpoint");
  let checkpoint = job.checkpoint;
  try {
    for (; checkpoint < stages.length; checkpoint++) {
      await advanceJob(job, checkpoint, "heartbeat");
      await stages[checkpoint](job);
      await advanceJob(job, checkpoint + 1, "checkpoint");
    }
    await advanceJob(job, checkpoint, "succeeded");
  } catch (error) {
    // If acknowledgement is uncertain the persisted checkpoint is authoritative.
    // A stale worker cannot reset it or finalize a replacement worker's result.
    await advanceJob(job, checkpoint, error instanceof PermanentJobError ? "dead" : "retry").catch(() => {});
    throw error;
  }
}

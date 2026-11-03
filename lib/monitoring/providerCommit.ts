import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { Finding } from "./findings";
import type { EdgeTrafficRecord, ProviderCommit, ProviderFailure } from "./registry";

const createdSchema = z.array(z.object({
  id: z.string().min(1), severity: z.enum(["CRITICAL", "WARNING", "INFO"]),
  title: z.string().min(1), consequence: z.string().min(1),
}));

/**
 * A commit capability bound to one claimed monitor job. The SQL function
 * rejects the write unless this job still holds its lease and the transport's
 * connection identity is unchanged, so a stale or reconnected worker writes
 * nothing. Only findings the commit newly inserted come back for alerting.
 */
export function fencedProviderCommit(userId: string, jobId: string, leaseToken: string): ProviderCommit {
  return async (result) => {
    const { data, error } = await getSupabaseAdmin().rpc("persist_provider_monitor_result", {
      p_user: userId, p_job: jobId, p_token: leaseToken,
      p_transport: result.transport, p_identity: result.identity,
      p_facts: result.facts ?? null, p_findings: result.findings,
      p_retire: result.retire, p_unread: result.unread ?? [],
      p_snapshot: result.snapshot,
    });
    const created = createdSchema.safeParse(data);
    if (error || !created.success) throw new Error("Provider result was not committed");
    return created.data as Finding[];
  };
}

/** Records a provider pass that read nothing usable, fenced by the same job
 * lease. The reason is a short code, never provider text. */
export function fencedProviderFailure(userId: string, jobId: string, leaseToken: string): ProviderFailure {
  return async (transport, reason) => {
    const { error } = await getSupabaseAdmin().rpc("record_provider_read_failure", {
      p_user: userId, p_job: jobId, p_token: leaseToken, p_transport: transport, p_scope: null, p_reason: reason,
    });
    if (error) throw new Error("Provider failure was not recorded");
  };
}

/** Records whether the Supabase gateway log was read (migration 088),
 * fenced by the same job lease. */
export function fencedEdgeTrafficRecord(userId: string, jobId: string, leaseToken: string): EdgeTrafficRecord {
  return async (projectRef, read) => {
    const { error } = await getSupabaseAdmin().rpc("record_edge_traffic_snapshot", {
      p_user: userId, p_job: jobId, p_token: leaseToken, p_project_ref: projectRef, p_read: read,
    });
    if (error) throw new Error("Edge traffic snapshot was not recorded");
  };
}

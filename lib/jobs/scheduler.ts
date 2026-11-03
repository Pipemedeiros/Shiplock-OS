import { z } from "zod";
import { BILLING_ENABLED } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { quotaCode } from "@/lib/quota";

const admission = z.object({
  eligible: z.number().int().nonnegative(),
  admitted: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  limited: z.boolean(),
}).refine((value) => value.admitted + value.failed === value.eligible);

type AuditAdmission = z.infer<typeof admission>;

/** Queues audits for selected repositories not audited in the last 48 hours. */
export async function admitDueRepositoryAudits(
  now = new Date(),
  limit = 1_000,
): Promise<AuditAdmission> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000 || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid audit admission window");
  }
  const cutoff = new Date(now.getTime() - 48 * 60 * 60 * 1_000).toISOString();
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_due_repository_audits", {
    p_cutoff: cutoff,
    p_day: now.toISOString().slice(0, 10),
    p_require_paid: BILLING_ENABLED,
    p_limit: limit,
  });
  if (error) throw new Error("Scheduled work could not be queued");
  return admission.parse(data);
}

/** Queues source scans for selected repositories not scanned in the last 48
 * hours. */
export async function admitDueRepositorySourceScans(
  now = new Date(),
  limit = 1_000,
): Promise<AuditAdmission> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000 || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid source admission window");
  }
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_due_repository_sources", {
    p_cutoff: new Date(now.getTime() - 48 * 60 * 60 * 1_000).toISOString(),
    p_day: now.toISOString().slice(0, 10),
    p_limit: limit,
  });
  if (error) throw new Error("Scheduled source work could not be queued");
  return admission.parse(data);
}

/** Queues dependency checks for selected repositories that are due. */
export async function admitDueRepositoryDependencyChecks(
  now = new Date(),
  limit = 1_000,
): Promise<AuditAdmission> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000 || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid dependency admission window");
  }
  const { data, error } = await getSupabaseAdmin().rpc(
    "enqueue_due_repository_dependencies",
    { p_day: now.toISOString().slice(0, 10), p_limit: limit },
  );
  if (error) throw new Error("Scheduled dependency work could not be queued");
  return admission.parse(data);
}

/** Queues the hourly or 48-hour provider monitoring passes that are due. */
export async function admitDueMonitoringPasses(
  trigger: "hourly" | "scheduled_48h",
  now = new Date(),
  limit = 1_000,
): Promise<AuditAdmission> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000 || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid monitoring admission window");
  }
  const hourly = trigger === "hourly";
  const cutoff = new Date(now.getTime() - (hourly ? 60 : 48 * 60) * 60 * 1_000).toISOString();
  const window = hourly ? now.toISOString().slice(0, 13) : now.toISOString().slice(0, 10);
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_due_monitoring_passes", {
    p_trigger: trigger,
    p_cutoff: cutoff,
    p_window: window,
    p_limit: limit,
  });
  if (error) throw new Error("Scheduled monitoring could not be queued");
  return admission.parse(data);
}

/** Weekly deep scans and windowed PR scans the customer approved. */
export async function admitDueIntelligenceScans(
  now = new Date(),
  limit = 1_000,
): Promise<AuditAdmission> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000 || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid intelligence admission window");
  }
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_due_intelligence_scans", {
    p_now: now.toISOString(),
    p_limit: limit,
  });
  if (error) throw new Error("Scheduled intelligence scans could not be queued");
  return admission.parse(data);
}

/** Queues one monitoring pass for an account, idempotent on `key`. */
export async function enqueueMonitoringPass(
  userId: string,
  trigger: "manual" | "deploy" | "hourly" | "scheduled_48h",
  key: string,
): Promise<string> {
  z.uuid().parse(userId);
  z.string().min(1).max(256).parse(key);
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_monitoring_job", {
    p_user: userId,
    p_trigger: trigger,
    p_key: key,
  });
  if (error) throw new Error(quotaCode(error.message) ?? "Monitoring could not be queued");
  return z.uuid().parse(data);
}

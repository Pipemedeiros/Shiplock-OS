import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * The latest self-check the customer's agent reported per open finding
 * (migration 107), keyed by the finding's row id. Agent output, shown on the
 * proof link as reported; an unreadable table is no report, never a result.
 */
export type SelfCheckReport = { status: number; host: string; reportedAt: string | null };

export async function loadSelfCheckReports(userId: string): Promise<Map<string, SelfCheckReport>> {
  const { data, error } = await getSupabaseAdmin().from("self_check_reports")
    .select("finding_row_id, status, target_host, reported_at").eq("user_id", userId).limit(500);
  if (error || !data) return new Map();
  return new Map((data as { finding_row_id: string; status: number; target_host: string; reported_at: string | null }[])
    .map((r) => [r.finding_row_id, { status: r.status, host: r.target_host, reportedAt: r.reported_at }]));
}

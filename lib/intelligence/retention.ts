import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/** Daily retention for customer-intelligence tasks (10B-1d, migration 075):
 * accepted results 30 days after completion, dead tasks after one day.
 * Fail-soft: called from a cron handler that must still return. */
export async function purgeIntelligenceTasks(): Promise<{ ok: boolean; purged: number }> {
  const { data, error } = await getSupabaseAdmin().rpc("purge_intelligence_tasks");
  const purged = z.number().int().nonnegative().safeParse(data);
  if (error || !purged.success) {
    console.error("[intelligence] retention purge failed");
    return { ok: false, purged: 0 };
  }
  return { ok: true, purged: purged.data };
}

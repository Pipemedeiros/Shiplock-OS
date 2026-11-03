import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/** Daily retention for provider snapshots (migration 087): 30 days, but
 * always the latest per account and transport. Fail-soft: called from a cron
 * handler that must still return. */
export async function pruneProviderSnapshots(): Promise<{ ok: boolean; pruned: number }> {
  const { data, error } = await getSupabaseAdmin().rpc("prune_provider_snapshots");
  const pruned = z.number().int().nonnegative().safeParse(data);
  if (error || !pruned.success) {
    console.error("[monitoring] provider snapshot prune failed");
    return { ok: false, pruned: 0 };
  }
  return { ok: true, pruned: pruned.data };
}

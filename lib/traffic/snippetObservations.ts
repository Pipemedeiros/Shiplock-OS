import { getSupabaseAdmin } from "@/lib/supabase";
import { collectSnippetHotPaths } from "./graphFacts";

/**
 * Writes this repository's snippet traffic as observations (X2, 2026-10-12),
 * so the hot routes, the rate-limit offer and its database check (093) see
 * the customer-side snippet, not only gateway logs. Counts come from sources
 * already flagged, bound through the repository's traffic site; the previous
 * set is replaced, so a stopped attack stops being offered.
 */
export async function syncSnippetObservations(userId: string, repositoryId: string): Promise<number> {
  const paths = await collectSnippetHotPaths(userId, repositoryId);
  const { data, error } = await getSupabaseAdmin().rpc("replace_traffic_observations", {
    p_user: userId, p_repository: repositoryId, p_source: "snippet", p_paths: paths,
  });
  if (error) throw new Error(`snippet observations not written: ${error.message}`);
  return Number(data ?? 0);
}

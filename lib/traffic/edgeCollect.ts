import { fetchEdgeRequestLog } from "@/lib/deep/supabaseMgmt";
import { getSupabaseRepositoryBindings } from "@/lib/deep/supabaseRepositoryBinding";
import { getSupabaseAdmin } from "@/lib/supabase";
import { analyzeEdgeRequests, dailySalt } from "./edgeRequests";

/**
 * No-install traffic: the customer's Supabase API gateway log, read
 * with their own Supabase connection, judged per source, and stored per
 * repository they confirmed for that Supabase project. An unreadable log is
 * "unread" and leaves prior observations untouched; no binding means nothing
 * is fetched at all.
 */
export type EdgeCollection =
  | { status: "read"; repositories: number; judgedSources: number }
  | { status: "unread" }
  | { status: "unbound" }
  | { status: "not_enabled" };

export async function collectSupabaseEdgeTraffic(
  userId: string, accessToken: string, projectRef: string, signal?: AbortSignal,
): Promise<EdgeCollection> {
  // Same entitlement as the snippet (sites.ts): traffic requires is_paid while
  // free vs paid is parked by Felipe. Do not widen it here.
  const { data: profile } = await getSupabaseAdmin().from("user_profiles").select("is_paid").eq("id", userId).maybeSingle();
  if (profile?.is_paid !== true) return { status: "not_enabled" };
  const bindings = await getSupabaseRepositoryBindings(userId, "supabase-management");
  if (!bindings.available || bindings.projectRef !== projectRef || bindings.bindings.length === 0) return { status: "unbound" };

  const log = await fetchEdgeRequestLog(accessToken, projectRef, signal);
  if (!log.ok) return { status: "unread" };
  const key = process.env.ENCRYPTION_KEY;
  if (!key) return { status: "unread" };
  const analysis = analyzeEdgeRequests(log.rows, dailySalt(key));
  if (!analysis.readable) return { status: "unread" };

  for (const { repositoryId } of bindings.bindings) {
    signal?.throwIfAborted();
    const { error } = await getSupabaseAdmin().rpc("replace_traffic_observations", {
      p_user: userId, p_repository: repositoryId, p_source: "supabase", p_paths: analysis.hotPaths,
    });
    if (error) throw new Error("traffic observations could not be stored");
  }
  return { status: "read", repositories: bindings.bindings.length, judgedSources: analysis.judged.length };
}

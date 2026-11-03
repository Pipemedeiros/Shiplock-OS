import { getSupabaseAdmin } from "@/lib/supabase";
import { getSupabaseRepositoryBindings } from "@/lib/deep/supabaseRepositoryBinding";

/**
 * Where each selected repository's traffic view comes from: its
 * snippet sites (085) and the Supabase gateway log read (086, snapshots 088).
 * No source is said plainly; an unread log is not a source.
 */
export type GatewayState = "read" | "unread" | "never_read" | "unbound" | "not_connected" | "not_enabled";
export type TrafficSourceStatus = {
  repositoryId: string; repository: string; sites: number; gateway: GatewayState;
  observedAt: string | null; hasSource: boolean;
};
export type TrafficSourceInput = {
  repositories: { id: string; fullName: string }[];
  sites: { repositoryId: string }[];
  paid: boolean;
  supabase: { connected: boolean; projectRef: string | null; boundRepositoryIds: string[] } | null;
  edge: { completeness: "complete" | "partial" | "failed"; observedAt: string; scope: string | null } | null;
};

export function summarizeTrafficSources(input: TrafficSourceInput): TrafficSourceStatus[] {
  const edge = input.edge && input.supabase && input.edge.scope === input.supabase.projectRef ? input.edge : null;
  return input.repositories.map((repository) => {
    const sites = input.sites.filter((site) => site.repositoryId === repository.id).length;
    let gateway: GatewayState;
    if (!input.paid) gateway = "not_enabled";
    else if (!input.supabase?.connected) gateway = "not_connected";
    else if (!input.supabase.boundRepositoryIds.includes(repository.id)) gateway = "unbound";
    else if (!edge) gateway = "never_read";
    else gateway = edge.completeness === "complete" ? "read" : "unread";
    const observedAt = gateway === "read" || gateway === "unread" ? edge!.observedAt : null;
    return { repositoryId: repository.id, repository: repository.fullName, sites, gateway, observedAt,
      hasSource: sites > 0 || gateway === "read" };
  });
}

export async function getTrafficSources(userId: string): Promise<{ available: boolean; items: TrafficSourceStatus[] }> {
  const admin = getSupabaseAdmin();
  try {
    const [repos, sites, profile, edge, bindings] = await Promise.all([
      admin.from("repositories").select("id, full_name").eq("user_id", userId).eq("selected", true),
      admin.from("traffic_sites").select("repository_id").eq("user_id", userId).is("revoked_at", null),
      admin.from("user_profiles").select("is_paid").eq("id", userId).maybeSingle(),
      admin.from("provider_snapshots").select("completeness, observed_at, scope")
        .eq("user_id", userId).eq("transport", "supabase-edge-logs").order("observed_at", { ascending: false }).limit(1),
      getSupabaseRepositoryBindings(userId, "supabase-management"),
    ]);
    if (repos.error || sites.error || profile.error || edge.error) return { available: false, items: [] };
    const latest = (edge.data ?? [])[0] as { completeness: "complete" | "partial" | "failed"; observed_at: string; scope: string | null } | undefined;
    return { available: true, items: summarizeTrafficSources({
      repositories: (repos.data ?? []).map((r) => ({ id: r.id as string, fullName: r.full_name as string })),
      sites: (sites.data ?? []).map((s) => ({ repositoryId: s.repository_id as string })),
      paid: profile.data?.is_paid === true,
      supabase: bindings.available
        ? { connected: true, projectRef: bindings.projectRef ?? null, boundRepositoryIds: bindings.bindings.map((b) => b.repositoryId) }
        : null,
      edge: latest ? { completeness: latest.completeness, observedAt: latest.observed_at, scope: latest.scope } : null,
    }) };
  } catch {
    return { available: false, items: [] };
  }
}

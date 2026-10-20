import { getSupabaseAdmin } from "@/lib/supabase";
import { API_PATH } from "./shippedCalls";

/**
 * Watch for the outside view: the backend addresses the live site started or
 * stopped requesting since the last read of the same address (a deploy
 * usually). A new address is new surface nobody reviewed. Claimed only
 * between two complete reads (every page and script read), since a partial
 * read can miss a request that is still there; otherwise not comparable,
 * never "no change".
 */
export type SurfaceChange =
  | { comparable: true; since: string | null; added: string[]; removed: string[] }
  | { comparable: false; since: string | null };

type Previous = { url?: unknown; complete?: unknown; requests?: unknown; recordedAt?: string | null } | null;

export function surfaceChange(previous: Previous, requests: readonly string[], complete: boolean, url: string): SurfaceChange {
  const since = previous?.recordedAt ?? null;
  const before = previous && previous.url === url && previous.complete === true && Array.isArray(previous.requests)
    ? new Set((previous.requests as unknown[]).filter((p): p is string => typeof p === "string" && API_PATH.test(p))) : null;
  if (!before || !complete) return { comparable: false, since };
  const now = new Set(requests.filter((p) => API_PATH.test(p)));
  return { comparable: true, since, added: [...now].filter((p) => !before.has(p)).sort(), removed: [...before].filter((p) => !now.has(p)).sort() };
}

/** The last stored read of the live site, with when it was recorded; null when none or unreadable. */
export async function loadPreviousSurface(userId: string): Promise<Previous> {
  const { data, error } = await getSupabaseAdmin().from("graph_facts").select("facts").eq("user_id", userId).eq("collector", "runtime").maybeSingle();
  if (error || !data) return null;
  const facts = data.facts as { appSurface?: Record<string, unknown>; _evidence?: { fields?: { appSurface?: { recordedAt?: unknown } } } } | null;
  const recordedAt = facts?._evidence?.fields?.appSurface?.recordedAt;
  return facts?.appSurface ? { ...facts.appSurface, recordedAt: typeof recordedAt === "string" ? recordedAt : null } : null;
}

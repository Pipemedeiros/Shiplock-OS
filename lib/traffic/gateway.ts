import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * What the customer's Supabase API gateway saw from flagged sources,
 * read through their Supabase connection with no snippet: each path, how many
 * suspicious requests reached it, and how many were answered with success
 * (migration 105; null when not counted). A success from PostgREST can be an
 * empty list, so this says answered, never that data was taken.
 */
export type GatewayPath = { path: string; label: string; suspiciousRequests: number; answered: number | null; observedAt: string };

/** A readable name for a Supabase gateway path: a table, function or storage
 * bucket. */
export function gatewayLabel(path: string): string {
  const seg = path.split("?")[0].split("/").filter(Boolean);
  if (seg[0] === "rest" && seg[2] === "rpc" && seg[3]) return `Database function ${seg[3]}`;
  if (seg[0] === "rest" && seg[2]) return `Table ${seg[2]}`;
  if (seg[0] === "storage") {
    const i = seg.findIndex((s) => s === "public" || s === "list" || s === "sign" || s === "authenticated");
    const bucket = i >= 0 ? seg[i + 1] : seg[3];
    if (bucket) return `Storage bucket ${bucket}`;
  }
  if (seg[0] === "auth") return "Sign in";
  if (seg[0] === "functions" && seg[2]) return `Edge function ${seg[2]}`;
  if (seg[0] === "graphql") return "GraphQL";
  return path;
}

/** Null when the read failed (unknown), never an empty list that reads as quiet. */
export async function loadGatewayPaths(userId: string): Promise<GatewayPath[] | null> {
  const { data, error } = await getSupabaseAdmin().from("traffic_route_observations")
    .select("path, suspicious_requests, answered, observed_at").eq("user_id", userId).eq("source", "supabase")
    .order("suspicious_requests", { ascending: false }).limit(20);
  if (error) return null;
  return ((data ?? []) as { path: string; suspicious_requests: number; answered: number | null; observed_at: string }[])
    .map((r) => ({ path: r.path, label: gatewayLabel(r.path), suspiciousRequests: r.suspicious_requests, answered: r.answered, observedAt: r.observed_at }));
}

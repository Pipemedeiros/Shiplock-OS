import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Pull requests ShipLock opened after the customer's click: every
 * lane's receipt, with the merge time the webhook stamps (084). A merge queues
 * a recheck of the default branch; ShipLock never merges.
 */
export type OpenedPullRequest = {
  id: string; lane: string; repository: string; number: number; url: string;
  mergedAt: string | null; requestedAt: string;
};

const LANES: Record<string, string> = {
  "risk-fix-pr": "Fix", "finding-fix-pr": "Fix", "dependency-bump-pr": "Dependency update",
  "pr-fix-pr": "Fix before merge", "ai-fix-pr": "Your AI's fix",
};

const row = z.object({
  id: z.uuid(), action: z.string(), pr_number: z.number().int().positive(),
  pr_url: z.string().regex(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/pull\/[0-9]+$/),
  merged_at: z.string().nullable(), requested_at: z.string(),
  repositories: z.object({ full_name: z.string() }),
});

export async function getOpenedPullRequests(userId: string): Promise<{ available: boolean; items: OpenedPullRequest[] }> {
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await getSupabaseAdmin().from("repair_action_receipts")
    .select("id, action, pr_url, pr_number, merged_at, requested_at, repositories(full_name)")
    .eq("user_id", userId).eq("status", "opened").gte("requested_at", since)
    .order("requested_at", { ascending: false }).limit(50);
  if (error || !Array.isArray(data)) return { available: false, items: [] };
  const items = data.flatMap((raw) => {
    const parsed = row.safeParse(raw);
    if (!parsed.success) return [];
    const r = parsed.data;
    return [{ id: r.id, lane: LANES[r.action] ?? "Fix", repository: r.repositories.full_name, number: r.pr_number,
      url: r.pr_url, mergedAt: r.merged_at, requestedAt: r.requested_at }];
  });
  return { available: true, items };
}

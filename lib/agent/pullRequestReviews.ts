import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

const findingSchema = z.object({
  id: z.string(), severity: z.enum(["CRITICAL", "WARNING"]), title: z.string(),
  detail: z.string(), file: z.string(), evidence: z.string(),
});
const rowSchema = z.object({
  id: z.uuid(), pull_request_number: z.number().int().positive(), head_sha: z.string(),
  head_ref: z.string().nullable(), same_repository: z.boolean().nullable(),
  title: z.string().nullable(), url: z.string().nullable(),
  verdict: z.enum(["pass", "warn", "block"]), coverage_complete: z.boolean(),
  checked_at: z.string(), findings: z.array(findingSchema),
  repositories: z.object({ full_name: z.string() }),
});

export type PullRequestReviewView = {
  id: string; repository: string; number: number; headSha: string; title: string | null; url: string | null;
  headRef: string | null; sameRepository: boolean | null;
  verdict: "pass" | "warn" | "block"; coverageComplete: boolean; checkedAt: string;
  findings: z.infer<typeof findingSchema>[];
};

/** What ShipLock found on the customer's recent pull requests (8B-2), newest
 * first, from reviews stored under each PR check's lease. */
export async function getRecentPullRequestReviews(userId: string, limit = 20): Promise<PullRequestReviewView[]> {
  const { data, error } = await getSupabaseAdmin().from("pull_request_reviews")
    .select("id, pull_request_number, head_sha, head_ref, same_repository, title, url, verdict, coverage_complete, checked_at, findings, repositories(full_name)")
    .eq("user_id", userId).order("checked_at", { ascending: false }).limit(limit);
  if (error) throw new Error("Pull request reviews could not be read");
  return (data ?? []).flatMap((raw) => {
    const row = rowSchema.safeParse(raw);
    if (!row.success) return [];
    const r = row.data;
    return [{
      id: r.id, repository: r.repositories.full_name, number: r.pull_request_number, headSha: r.head_sha, title: r.title, url: r.url,
      headRef: r.head_ref, sameRepository: r.same_repository, verdict: r.verdict,
      coverageComplete: r.coverage_complete, checkedAt: r.checked_at, findings: r.findings,
    }];
  });
}

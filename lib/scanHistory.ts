import { getSupabaseAdmin } from "@/lib/supabase";
import type { PreviewIssue, FullIssue } from "@/lib/types";

export interface LatestScan {
  issue_count: number | null;
  preview_issues: PreviewIssue[] | null;
  full_issues: FullIssue[] | null;
  created_at: string | null;
  // Hash only, never the raw project URL. scan_history also has a legacy, always-NULL
  // `project_url` text column (nothing writes to it — app/api/scan/
  // route.ts only ever inserts project_url_hash); this used to select
  // that dead column instead of this one, so every "your project" display
  // was silently blank. Fixed 2026-07-11 during a post-ship audit.
  project_url_hash: string | null;
}



/** The account's most recent endpoint scan. */
export async function getLatestScan(userId: string): Promise<LatestScan | null> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("scan_history")
    .select("issue_count, preview_issues, full_issues, created_at, project_url_hash")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return data as LatestScan | null;
}

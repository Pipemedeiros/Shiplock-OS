import { getSupabaseAdmin } from "@/lib/supabase";
import type { PreviewIssue, FullIssue, Grade } from "@/lib/types";

export interface LatestScan {
  grade: Grade | null;
  issue_count: number | null;
  preview_issues: PreviewIssue[] | null;
  full_issues: FullIssue[] | null;
  created_at: string | null;
  project_url: string | null;
}

// Server-only — same rule as getSupabaseAdmin() itself: never import this
// from client components. full_issues has no SELECT grant for
// `authenticated`, even for the row's own owner (migrations 012/013/016;
// verified live via information_schema.column_privileges) — the RLS-scoped
// client used elsewhere in server pages can never read it. This must go
// through the service-role client, same as app/api/scan/route.ts does.
export async function getLatestScan(userId: string): Promise<LatestScan | null> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("scan_history")
    .select("grade, issue_count, preview_issues, full_issues, created_at, project_url")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return data as LatestScan | null;
}

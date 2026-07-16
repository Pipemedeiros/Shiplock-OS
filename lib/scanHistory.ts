import { getSupabaseAdmin } from "@/lib/supabase";
import type { PreviewIssue, FullIssue } from "@/lib/types";

export interface LatestScan {
  issue_count: number | null;
  preview_issues: PreviewIssue[] | null;
  full_issues: FullIssue[] | null;
  created_at: string | null;
  // Hash only, never the raw URL — see security.md's "never store raw
  // projectUrl" rule. scan_history also has a legacy, always-NULL
  // `project_url` text column (nothing writes to it — app/api/scan/
  // route.ts only ever inserts project_url_hash); this used to select
  // that dead column instead of this one, so every "your project" display
  // was silently blank. Fixed 2026-07-11 during a post-ship audit.
  project_url_hash: string | null;
}

// Server-only — same rule as getSupabaseAdmin() itself: never import this
// from client components. full_issues has no SELECT grant for
// `authenticated`, even for the row's own owner (migrations 012/013/016;
// verified live via information_schema.column_privileges) — the RLS-scoped
// client used elsewhere in server pages can never read it. This must go
// through the service-role client, same as app/api/scan/route.ts does.
export interface ScanTimelineEntry {
  issue_count: number | null;
  created_at: string | null;
}

// Preview-safe fields only (count/date — the same data preview_issues callers
// may already see), so no paywall filtering is needed at the call site. Still
// service-role for the same grant reasons as getLatestScan.
export async function getScanTimeline(userId: string, limit = 8): Promise<ScanTimelineEntry[]> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("scan_history")
    .select("issue_count, created_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(limit);
  return (data ?? []) as ScanTimelineEntry[];
}

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

-- 016_fix_full_issues_column_grant_again.sql
-- 013 intended to revoke table-wide SELECT on scan_history and re-grant only
-- safe columns to authenticated, excluding full_issues. Confirmed live during
-- the 2026-07-01 follow-up audit that this did NOT hold: information_schema
-- .column_privileges showed `authenticated` still had column-level SELECT on
-- every column, including full_issues — an authenticated free user could read
-- their own fix/codefix directly via GET /rest/v1/scan_history?select=full_issues,
-- bypassing the app-level paywall in app/api/scan/route.ts entirely.
--
-- Re-running the same statements as 013. If this regresses a third time,
-- suspect an external process (Supabase's own default "GRANT ALL ON ALL
-- TABLES" applied on schema change, a dashboard action, or another migration
-- runner) re-broadening the grant after 013 ran, not a mistake in 013's SQL
-- itself — the SQL below is correct and was verified column-by-column via
-- information_schema.column_privileges after applying.
REVOKE SELECT ON public.scan_history FROM authenticated, anon;

GRANT SELECT (id, user_id, project_url, project_url_hash, grade, issue_count, preview_issues, created_at)
  ON public.scan_history TO authenticated;

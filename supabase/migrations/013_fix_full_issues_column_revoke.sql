-- 013_fix_full_issues_column_revoke.sql
-- 012 revoked column-level SELECT on full_issues, but Supabase's default
-- table-wide "GRANT ALL ON ALL TABLES" to authenticated/anon already grants
-- table-level SELECT, which satisfies the privilege check regardless of a
-- more specific column-level revoke (column grants only add to a MORE
-- restrictive baseline, they don't subtract from a table-wide grant).
-- Must revoke table-level SELECT first, then re-grant only the safe columns.
REVOKE SELECT ON public.scan_history FROM authenticated, anon;

GRANT SELECT (id, user_id, project_url, project_url_hash, grade, issue_count, preview_issues, created_at)
  ON public.scan_history TO authenticated;

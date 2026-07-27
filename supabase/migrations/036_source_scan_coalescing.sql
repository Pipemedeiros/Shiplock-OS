-- 036 — coalesce bursty per-PR source scans
--
-- The GitHub PR webhook fires `synchronize` on EVERY push to an open pull
-- request, and runGithubScan re-scans the whole repo set from scratch each
-- time. Twenty pushes to one PR — or a batch of Dependabot PRs — meant twenty
-- full scans: hundreds of GitHub API calls against a 5,000/hour installation
-- token limit, almost always for identical results.
--
-- This column records when the source scan last ran so the webhook can collapse
-- a burst into one scan. Nothing is skipped: the hourly critical pass and the
-- 48-hour deep scan run regardless.
--
-- NOTE: the grants are re-applied at the bottom. New columns inherit the
-- table-level grant, so every migration that adds one silently re-widens
-- `anon`/`authenticated` access — see migration 035 for the full write-up.
-- Re-assert least privilege in the same transaction that adds the column.

alter table public.user_profiles
  add column if not exists last_source_scan_at timestamptz;

comment on column public.user_profiles.last_source_scan_at is
  'When the per-PR GitHub source scan last ran. Used by /api/monitor/github to '
  'collapse a burst of push events into a single scan. Service-role only.';

revoke all on public.user_profiles from anon;
revoke insert, update, delete, references on public.user_profiles from authenticated;
revoke select on public.user_profiles from authenticated;
grant select (id, is_paid) on public.user_profiles to authenticated;

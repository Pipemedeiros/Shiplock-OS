-- 038 — weekly digest send tracking
--
-- Alerts fire only on NEW findings, which is correct — silence is the default.
-- But it means a customer four months in hears nothing, and "nothing is wrong"
-- is indistinguishable from "this product is dead". They cancel while it works.
--
-- The digest is a receipt, not an alert: passes run, requests checked, threats
-- turned away, findings resolved. This column is the once-a-week guard, checked
-- by the daily cron so the send rides existing infrastructure rather than
-- needing a weekly schedule (the Vercel plan only allows daily crons anyway).
--
-- Grants re-asserted: a new column inherits the table-level grant and would
-- otherwise silently re-widen anon/authenticated access. See migration 035.

alter table public.user_profiles
  add column if not exists last_digest_sent_at timestamptz;

comment on column public.user_profiles.last_digest_sent_at is
  'When the weekly digest last went out. Guards the once-a-week cadence from '
  'the daily cron. Service-role only.';

create index if not exists idx_user_profiles_digest_due
  on public.user_profiles (last_digest_sent_at)
  where is_paid = true;

revoke all on public.user_profiles from anon;
revoke insert, update, delete, references on public.user_profiles from authenticated;
revoke select on public.user_profiles from authenticated;
grant select (id, is_paid) on public.user_profiles to authenticated;

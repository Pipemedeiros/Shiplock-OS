-- 032_monitored_app_url.sql
-- Persist the customer's live app URL (the optional third scan input) so
-- dynamic exposed-path probes can run against it later, not just at scan time.
-- Raw, like monitored_project_url (a re-probe needs a real address; the privacy
-- page discloses it). Nullable — most scans don't provide an app URL.
alter table public.user_profiles
  add column if not exists monitored_app_url text;

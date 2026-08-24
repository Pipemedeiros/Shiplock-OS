-- 044_hourly_pass_fairness.sql
-- Per-pass-type recency stamp, so the hourly pass can be fair.
--
-- The hourly route iterates every enrolled user inside a 60s serverless
-- function with no ordering and no limit. Once the customer count times the
-- per-customer cost exceeds the ceiling, the function is cut off partway
-- through — and because the query has no ORDER BY, the users it reaches are
-- whatever order Postgres happened to return. In practice that is stable, which
-- is the worst case: the same early users get monitored every hour and the ones
-- past the cutoff are never monitored at all, silently, while their dashboard
-- still says monitoring is on.
--
-- Ordering by staleness fixes it — whoever waited longest goes first, so the
-- backlog rotates and nobody starves. That needs a stamp the hourly pass owns.
-- last_monitored_at cannot be reused: it deliberately tracks only FULL scans,
-- because the 48h staleness filter keys on it and an hourly pass refreshing it
-- would keep every user perpetually "recently scanned" and stop the deep scan
-- from ever running again (see the comment in lib/monitoring/run.ts).
--
-- NULL means never processed by an hourly pass, and NULLS FIRST ordering puts
-- those users at the front — a new customer should not wait behind the whole
-- existing base for their first pass.
--
-- This is a fairness fix, not a scale fix. It guarantees the queue rotates; it
-- does not raise the ~15-20 customer ceiling, which needs the job queue.

alter table public.user_profiles
  add column if not exists last_hourly_pass_at timestamptz;

comment on column public.user_profiles.last_hourly_pass_at is
  'When the hourly critical-check pass last processed this user. Ordering key for fairness — NULL (never processed) sorts first. Distinct from last_monitored_at, which tracks full scans only.';

-- Partial index on the ordering key. The pass reads only enrolled users, so the
-- index carries the same predicate rather than covering the whole table.
create index if not exists user_profiles_hourly_pass_idx
  on public.user_profiles (last_hourly_pass_at nulls first)
  where monitoring_enabled = true;

-- No grant changes: user_profiles is locked to service-role for these columns
-- (migrations 035/041), and this is internal scheduling state that no browser
-- has any reason to read.

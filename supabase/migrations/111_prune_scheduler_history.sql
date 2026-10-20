-- 111: keep the scheduler's own run log bounded (Felipe 2026-10-20: storage
-- stays on the free plan).
--
-- pg_cron writes one cron.job_run_details row per run, and the minute worker
-- (094) runs every minute. Nothing pruned them: on 2026-10-20 the log held
-- 29,327 rows and 33 MB, the largest table in a 52 MB database, and grows by
-- about 1,440 rows a day. Once a day, rows older than 7 days are removed. Only
-- the scheduler's run history is touched; no application row is.
--
-- Where pg_cron is unavailable (the local PGlite suite) this is a no-op.
do $migration$
begin
  if not exists (select 1 from pg_available_extensions where name = 'pg_cron') then
    raise notice 'pg_cron unavailable: scheduler history prune not scheduled';
    return;
  end if;

  create extension if not exists pg_cron;

  perform cron.schedule('shiplock-prune-scheduler-history', '17 3 * * *', $job$
    delete from cron.job_run_details where end_time < now() - interval '7 days';
  $job$);
end
$migration$;

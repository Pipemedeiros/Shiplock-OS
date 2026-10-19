-- 108: a newer queued scheduled job supersedes older queued copies of itself.
-- The daily scheduler admits monitor, source, dependency and graph jobs per
-- day, and deep agent scans per week. When no worker ran (the minute wake
-- needs shiplock_cron_secret), each day added another copy on top of the
-- last: production held 81 queued copies on 2026-10-19, and a customer's
-- "check now" woke the queue onto the oldest. Each copy reads the same
-- current state, so only the newest per account, kind and repository is
-- kept. Only scheduled keys are touched; manual and pull-request work,
-- running jobs, and audits (097) never. Same advisory lock as the claim.
create or replace function public.supersede_stale_scheduled_jobs()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare n integer;
begin
  perform pg_advisory_xact_lock(73610423);
  with ranked as (
    select j.id, row_number() over (partition by j.user_id, j.kind, j.repository_id
      order by j.created_at desc, j.id desc) as rn
    from public.execution_jobs j
    where j.status = 'queued' and j.kind in ('monitor', 'source', 'dependency', 'graph', 'intelligence')
      and (j.deduplication_key like 'scheduled-%' or j.deduplication_key like 'intel-deep:%')
  ), cancelled as (
    update public.execution_jobs j set status = 'cancelled', error_code = 'cancelled', lease_token = null,
      lease_until = null, finished_at = now(), updated_at = now()
    from ranked where j.id = ranked.id and ranked.rn > 1 and j.status = 'queued'
    returning j.id
  )
  select count(*) into n from cancelled;
  return n;
end $$;

revoke all on function public.supersede_stale_scheduled_jobs() from public, anon, authenticated;
grant execute on function public.supersede_stale_scheduled_jobs() to service_role;

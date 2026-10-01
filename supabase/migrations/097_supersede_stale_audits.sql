-- 097: a newer queued audit of a repository supersedes older queued ones.
-- The queue claims oldest first, so without this a customer's "Run audit"
-- click ran a days-old scheduled audit instead, and daily scheduled audits
-- piled up whenever no worker was running. Only queued manual or scheduled
-- audits are touched; running jobs, pull-request audits and other kinds never.
-- Same advisory lock as claim_execution_job, so a claim cannot race it.
create or replace function public.supersede_stale_audits()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare n integer;
begin
  perform pg_advisory_xact_lock(73610423);
  with ranked as (
    select j.id, j.audit_run_id,
      row_number() over (partition by j.repository_id order by j.created_at desc, j.id desc) as rn
    from public.execution_jobs j join public.audit_runs r on r.id = j.audit_run_id
    where j.kind = 'audit' and j.status = 'queued' and r.status = 'queued' and r.trigger in ('manual', 'scheduled')
  ), cancelled as (
    update public.execution_jobs j set status = 'cancelled', error_code = 'cancelled', lease_token = null,
      lease_until = null, finished_at = now(), updated_at = now()
    from ranked where j.id = ranked.id and ranked.rn > 1 and j.status = 'queued'
    returning j.audit_run_id
  ), failed as (
    update public.audit_runs r set status = 'failed', finished_at = now(), audit_execution_token = null,
      error = 'Replaced by a newer audit of this repository.'
    from cancelled where r.id = cancelled.audit_run_id and r.status = 'queued'
    returning r.id
  )
  select count(*) into n from cancelled;
  return n;
end $$;

revoke all on function public.supersede_stale_audits() from public, anon, authenticated;
grant execute on function public.supersede_stale_audits() to service_role;

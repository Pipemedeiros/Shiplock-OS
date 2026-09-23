-- Hard per-account cap on manual audits (Step 3H-1). A manual audit is a
-- customer click; each one reads a GitHub archive and occupies a worker, and
-- after the first-scan credit (081) it spends no model tokens but is still not
-- free to run. At most 20 manual audits per account in any rolling 24 hours.
-- The number is PROVISIONAL (AGENTS.md: quotas are measured and approved
-- before launch). Scheduled and pull-request audits have their own
-- deduplication keys and are not counted. An idempotent replay of an admitted
-- click is never refused.

create or replace function public.enqueue_repository_audit(
  p_user uuid,
  p_repository uuid,
  p_key text,
  p_trigger text default 'manual'
)
returns table(job_id uuid, run_id uuid)
language plpgsql security definer set search_path = pg_catalog, public as $$
declare repository_name text;
begin
  if p_key is null or length(p_key) not between 1 and 256 then
    raise exception 'invalid key';
  end if;
  if p_trigger is null or p_trigger not in ('manual','pull_request','scheduled') then
    raise exception 'invalid audit trigger';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user::text,73610423));
  select full_name into repository_name from public.repositories
    where id=p_repository and user_id=p_user and selected=true for update;
  if not found then raise exception 'repository unavailable'; end if;

  select j.id,j.audit_run_id into job_id,run_id from public.execution_jobs j
    where j.user_id=p_user and j.kind='audit' and j.deduplication_key=p_key;
  if found then
    if run_id is null
      or exists(
        select 1 from public.execution_jobs j
          where j.id=job_id and j.repository_id is distinct from p_repository
      )
      or exists(
        select 1 from public.audit_runs r
          where r.id=run_id and r.trigger is distinct from p_trigger
      )
    then raise exception 'idempotency context mismatch'; end if;
    return next;
    return;
  end if;

  if p_trigger = 'manual' and (select count(*) from public.audit_runs
      where user_id = p_user and trigger = 'manual' and started_at > now() - interval '24 hours') >= 20 then
    raise exception 'audit quota reached';
  end if;

  if (select count(*) from public.execution_jobs
      where user_id=p_user and status in ('queued','running')) >= 100 then
    raise exception 'queue capacity reached';
  end if;

  insert into public.audit_runs(user_id,repository_id,full_name,status,trigger)
    values(p_user,p_repository,repository_name,'queued',p_trigger)
    returning id into run_id;
  insert into public.execution_jobs(user_id,repository_id,audit_run_id,kind,deduplication_key)
    values(p_user,p_repository,run_id,'audit',p_key)
    returning id into job_id;
  return next;
end $$;

revoke all on function public.enqueue_repository_audit(uuid,uuid,text,text)
  from public,anon,authenticated;
grant execute on function public.enqueue_repository_audit(uuid,uuid,text,text)
  to service_role;

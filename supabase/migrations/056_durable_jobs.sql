-- ShipLock-owned execution state. No customer source, provider token or payload
-- body belongs in this table. Jobs reference tenant-owned identities only.
alter table public.audit_runs add column audit_execution_token uuid;

create table public.execution_jobs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid,
  audit_run_id uuid unique references public.audit_runs(id) on delete cascade,
  kind text not null check (kind in ('audit', 'source', 'monitor', 'dependency', 'graph', 'pr-check')),
  deduplication_key text not null check (length(deduplication_key) between 1 and 256),
  status text not null default 'queued' check (status in ('queued','running','succeeded','dead','cancelled')),
  attempts integer not null default 0 check (attempts between 0 and 5),
  lease_token uuid,
  lease_until timestamptz,
  run_after timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  finished_at timestamptz,
  checkpoint integer not null default 0 check (checkpoint >= 0),
  error_code text check (error_code in ('worker_lost', 'execution_failed', 'context_changed', 'cancelled')),
  unique(user_id, kind, deduplication_key),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check ((status = 'running' and lease_token is not null and lease_until is not null)
    or (status <> 'running' and lease_token is null and lease_until is null)),
  check (kind not in ('audit','pr-check') or repository_id is not null),
  check ((kind='audit') = (audit_run_id is not null))
);
create index execution_jobs_ready on public.execution_jobs(run_after, created_at) where status = 'queued';
create index execution_jobs_leases on public.execution_jobs(lease_until) where status = 'running';
alter table public.execution_jobs enable row level security;
revoke all on public.execution_jobs from public, anon, authenticated;
grant select, insert, update, delete on public.execution_jobs to service_role;
grant select, insert, update, delete on public.provider_repository_links to service_role;

create function public.enqueue_execution_job(p_user uuid, p_repository uuid, p_kind text, p_key text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare job_id uuid;
begin
  -- Capacity and idempotency are tenant-local. Do not serialize 50,000 tenants
  -- behind the global claim lock just to enqueue independent work.
  perform pg_advisory_xact_lock(hashtextextended(p_user::text,73610423));
  if p_kind='audit' then raise exception 'use audit enqueue'; end if;
  if p_repository is not null and not exists (
    select 1 from public.repositories where id=p_repository and user_id=p_user and selected=true
  ) then raise exception 'repository unavailable'; end if;
  select id into job_id from public.execution_jobs
    where user_id=p_user and kind=p_kind and deduplication_key=p_key;
  if found then
    if exists(select 1 from public.execution_jobs where id=job_id and repository_id is distinct from p_repository)
      then raise exception 'idempotency context mismatch'; end if;
    return job_id;
  end if;
  if (select count(*) from public.execution_jobs where user_id=p_user and status in ('queued','running')) >= 100
    then raise exception 'queue capacity reached'; end if;
  insert into public.execution_jobs(user_id,repository_id,kind,deduplication_key)
    values(p_user,p_repository,p_kind,p_key) returning id into job_id;
  return job_id;
end $$;

-- Manual audit admission and its customer-visible run are one transaction. A
-- queued job without a run is invisible; a run without a job spins forever.
create function public.enqueue_repository_audit(p_user uuid, p_repository uuid, p_key text)
returns table(job_id uuid, run_id uuid) language plpgsql security definer set search_path = pg_catalog, public as $$
declare repository_name text;
begin
  if p_key is null or length(p_key) not between 1 and 256 then raise exception 'invalid key'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text,73610423));
  select full_name into repository_name from public.repositories
    where id=p_repository and user_id=p_user and selected=true for update;
  if not found then raise exception 'repository unavailable'; end if;
  select id,audit_run_id into job_id,run_id from public.execution_jobs
    where user_id=p_user and kind='audit' and deduplication_key=p_key;
  if found then
    if run_id is null or exists(select 1 from public.execution_jobs where id=job_id and repository_id is distinct from p_repository)
      then raise exception 'idempotency context mismatch'; end if;
    return next; return;
  end if;
  if (select count(*) from public.execution_jobs where user_id=p_user and status in ('queued','running')) >= 100
    then raise exception 'queue capacity reached'; end if;
  insert into public.audit_runs(user_id,repository_id,full_name,status,trigger)
    values(p_user,p_repository,repository_name,'queued','manual') returning id into run_id;
  insert into public.execution_jobs(user_id,repository_id,audit_run_id,kind,deduplication_key)
    values(p_user,p_repository,run_id,'audit',p_key) returning id into job_id;
  return next;
end $$;

create function public.claim_execution_job(p_kind text, p_lease_seconds integer default 120)
returns setof public.execution_jobs language plpgsql security definer set search_path = pg_catalog, public as $$
declare chosen uuid; chosen_token uuid;
begin
  if p_lease_seconds is null or p_lease_seconds < 30 or p_lease_seconds > 900 then raise exception 'invalid lease'; end if;
  perform pg_advisory_xact_lock(73610423);
  update public.audit_runs r set
    status=case when j.attempts>=5 then 'failed' else 'queued' end,
    audit_execution_token=null,
    finished_at=case when j.attempts>=5 then now() else null end,
    error=case when j.attempts>=5 then 'Audit execution stopped before completion.' else r.error end
    from public.execution_jobs j where j.audit_run_id=r.id and j.status='running'
      and j.lease_until<=now() and r.status<>'complete' and r.audit_execution_token=j.lease_token;
  update public.execution_jobs set status=case when attempts>=5 then 'dead' else 'queued' end,
    lease_token=null, lease_until=null, error_code='worker_lost', updated_at=now(),
    run_after=now()+least(300, power(2,attempts)::integer)*interval '1 second',
    finished_at=case when attempts>=5 then now() else null end
    where status='running' and lease_until<=now();
  -- Global and per-kind bounds plus one active job per tenant.
  if (select count(*) from public.execution_jobs where status='running') >= 8
    or (select count(*) from public.execution_jobs where status='running' and kind=p_kind) >= 2 then return; end if;
  select j.id into chosen from public.execution_jobs j
    where j.status='queued' and j.kind=p_kind and j.run_after<=now() and j.attempts<5
    and not exists(select 1 from public.execution_jobs busy where busy.user_id=j.user_id and busy.status='running')
    order by j.run_after,j.created_at,j.id for update skip locked limit 1;
  if chosen is null then return; end if;
  update public.execution_jobs set status='running', attempts=attempts+1,
    lease_token=gen_random_uuid(),lease_until=now()+p_lease_seconds*interval '1 second',updated_at=now()
    where id=chosen returning lease_token into chosen_token;
  -- The run token turns queue fencing into write fencing. Reclaim replaces it,
  -- so a stale audit worker cannot finish or fail the replacement worker's run.
  update public.audit_runs set audit_execution_token=chosen_token
    where id=(select audit_run_id from public.execution_jobs where id=chosen) and status<>'complete';
  return query select * from public.execution_jobs where id=chosen;
end $$;

create function public.advance_execution_job(p_id uuid,p_token uuid,p_checkpoint integer,p_outcome text)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
declare job public.execution_jobs;
begin
  if p_checkpoint is null or p_checkpoint<0 or p_outcome is null or p_outcome not in ('heartbeat','checkpoint','succeeded','retry','dead','cancelled')
    then raise exception 'invalid transition'; end if;
  select * into job from public.execution_jobs where id=p_id for update;
  if not found or job.status<>'running' or job.lease_token is distinct from p_token or job.lease_until<=now() then return false; end if;
  if p_checkpoint<job.checkpoint or p_checkpoint>job.checkpoint+1 then return false; end if;
  if job.audit_run_id is not null and
      (p_outcome in ('dead','cancelled') or (p_outcome='retry' and job.attempts>=5)) then
    update public.audit_runs set status='failed', audit_execution_token=null, finished_at=now(),
      error='Audit execution stopped before completion.'
      where id=job.audit_run_id and status<>'complete' and audit_execution_token=p_token;
  end if;
  update public.execution_jobs set
    status=case when p_outcome in ('heartbeat','checkpoint') then 'running'
      when p_outcome='retry' then case when attempts>=5 then 'dead' else 'queued' end else p_outcome end,
    checkpoint=p_checkpoint,
    lease_token=case when p_outcome in ('heartbeat','checkpoint') then lease_token else null end,
    lease_until=case when p_outcome in ('heartbeat','checkpoint') then now()+interval '120 seconds' else null end,
    run_after=case when p_outcome='retry' then now()+least(300,power(2,attempts)::integer)*interval '1 second' else run_after end,
    error_code=case when p_outcome in ('retry','dead') then 'execution_failed' when p_outcome='cancelled' then 'cancelled' else null end,
    finished_at=case when p_outcome in ('succeeded','dead','cancelled') or (p_outcome='retry' and attempts>=5) then now() else null end,
    updated_at=now()
    where id=p_id;
  return true;
end $$;

revoke all on function public.enqueue_execution_job(uuid,uuid,text,text) from public,anon,authenticated;
revoke all on function public.enqueue_repository_audit(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.claim_execution_job(text,integer) from public,anon,authenticated;
revoke all on function public.advance_execution_job(uuid,uuid,integer,text) from public,anon,authenticated;
grant execute on function public.enqueue_execution_job(uuid,uuid,text,text) to service_role;
grant execute on function public.enqueue_repository_audit(uuid,uuid,text) to service_role;
grant execute on function public.claim_execution_job(text,integer) to service_role;
grant execute on function public.advance_execution_job(uuid,uuid,integer,text) to service_role;

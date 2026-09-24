-- Durable proof jobs and proof records (Q6 / Step 6A-2).
-- A proof runs only from a customer's per-test authorization (090): enqueueing
-- consumes it and queues one `proof` job keyed by it, in one transaction. The
-- worker rebuilds that one table and its policies in an embedded, disposable
-- Postgres with synthetic tenants (no customer data, no paid host) and records
-- exactly one outcome under its live lease: could_not_test, ran (probes ran,
-- no leak), reproduced (a synthetic tenant read another tenant's row), or
-- aborted (budget or time limit). "ran" is never "secure".
alter table public.execution_jobs drop constraint execution_jobs_kind_check;
alter table public.execution_jobs add constraint execution_jobs_kind_check
  check (kind in ('audit','source','monitor','dependency','graph','pr-check','notification','repair','intelligence','proof'));

create table public.proof_runs (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  authorization_id uuid not null unique references public.proof_authorizations(id) on delete cascade,
  job_id uuid not null unique references public.execution_jobs(id) on delete cascade,
  finding_id text not null,
  table_name text not null,
  arena_kind text not null default 'replica' check (arena_kind in ('replica')),
  outcome text not null check (outcome in ('could_not_test','ran','reproduced','aborted')),
  reason text check (reason ~ '^[a-z_]{1,64}$'),
  statements_run integer not null check (statements_run between 0 and 200),
  finished_at timestamptz not null default now(),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check ((outcome in ('could_not_test','aborted')) = (reason is not null))
);
create index proof_runs_finding on public.proof_runs (user_id, repository_id, finding_id, finished_at desc);
alter table public.proof_runs enable row level security;
revoke all on public.proof_runs from public, anon, authenticated;
grant select, insert, delete on public.proof_runs to service_role;

create function public.enqueue_proof_job(p_user uuid, p_authorization uuid)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare auth public.proof_authorizations;
begin
  select * into auth from public.proof_authorizations where id = p_authorization and user_id = p_user for update;
  if not found then raise exception 'proof authorization unavailable'; end if;
  perform public.consume_proof_authorization(p_user, p_authorization);
  return public.enqueue_execution_job(p_user, auth.repository_id, 'proof', 'proof:' || auth.id::text);
end $$;

create function public.record_proof_run(
  p_user uuid, p_job uuid, p_token uuid, p_outcome text, p_reason text, p_statements integer
) returns void language plpgsql security definer set search_path = pg_catalog, public as $$
declare job public.execution_jobs; auth public.proof_authorizations;
begin
  select * into job from public.execution_jobs where id = p_job;
  if not found or job.user_id <> p_user or job.kind <> 'proof' or job.status <> 'running'
    or job.lease_token is distinct from p_token or job.lease_until <= now()
    or job.deduplication_key !~ '^proof:[0-9a-f-]{36}$' then
    raise exception 'proof lease unavailable';
  end if;
  select * into auth from public.proof_authorizations
    where id = substr(job.deduplication_key, 7)::uuid and user_id = p_user and status = 'consumed';
  if not found then raise exception 'proof authorization unavailable'; end if;
  if p_statements is null or p_statements > auth.statement_budget then raise exception 'invalid proof run'; end if;
  insert into public.proof_runs(user_id, repository_id, authorization_id, job_id, finding_id, table_name,
      outcome, reason, statements_run)
    values (p_user, auth.repository_id, auth.id, p_job, auth.finding_id, auth.table_name,
      p_outcome, p_reason, p_statements);
end $$;

revoke all on function public.enqueue_proof_job(uuid,uuid) from public, anon, authenticated;
grant execute on function public.enqueue_proof_job(uuid,uuid) to service_role;
revoke all on function public.record_proof_run(uuid,uuid,uuid,text,text,integer) from public, anon, authenticated;
grant execute on function public.record_proof_run(uuid,uuid,uuid,text,text,integer) to service_role;

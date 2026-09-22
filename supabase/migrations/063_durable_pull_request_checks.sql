-- Typed identity-only context for retryable pull-request checks. No diff,
-- source, token, or provider response is stored in the queue.
create table public.pull_request_jobs (
  job_id uuid primary key references public.execution_jobs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  pull_request_number integer not null check (pull_request_number>0),
  head_sha text not null check (head_sha ~ '^[A-Fa-f0-9]{7,64}$'),
  foreign key(repository_id,user_id) references public.repositories(id,user_id) on delete cascade,
  unique(user_id,repository_id,pull_request_number,head_sha)
);
alter table public.pull_request_jobs enable row level security;
revoke all on public.pull_request_jobs from public,anon,authenticated;
grant select,insert,update,delete on public.pull_request_jobs to service_role;

create function public.enqueue_pull_request_check(
  p_user uuid,
  p_repository uuid,
  p_key text,
  p_pull_request_number integer,
  p_head_sha text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare result_id uuid; existing_context public.pull_request_jobs;
begin
  if p_pull_request_number is null or p_pull_request_number<=0
    or p_head_sha is null or p_head_sha !~ '^[A-Fa-f0-9]{7,64}$' then
    raise exception 'invalid pull request context';
  end if;

  result_id := public.enqueue_execution_job(p_user,p_repository,'pr-check',p_key);
  select * into existing_context from public.pull_request_jobs where job_id=result_id;
  if found then
    if existing_context.user_id is distinct from p_user
      or existing_context.repository_id is distinct from p_repository
      or existing_context.pull_request_number is distinct from p_pull_request_number
      or existing_context.head_sha is distinct from lower(p_head_sha)
    then raise exception 'idempotency context mismatch'; end if;
    return result_id;
  end if;

  insert into public.pull_request_jobs(
    job_id,user_id,repository_id,pull_request_number,head_sha
  ) values(
    result_id,p_user,p_repository,p_pull_request_number,lower(p_head_sha)
  );
  return result_id;
end $$;

revoke all on function public.enqueue_pull_request_check(uuid,uuid,text,integer,text)
  from public,anon,authenticated;
grant execute on function public.enqueue_pull_request_check(uuid,uuid,text,integer,text)
  to service_role;

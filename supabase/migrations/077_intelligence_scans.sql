-- Scheduled customer-intelligence scans (Step 10B-2c). The customer's standing
-- approval (076) names a weekly deep scan and a PR-scan cadence; this admits
-- durable `intelligence` jobs on that schedule. A job carries identity only
-- (repository, and for PR scans the PR number and head commit); the worker
-- re-reads the approval, repository, and installation, picks the files, and
-- creates the task for the approved host. Nothing here calls a model or funds
-- one: the customer's own host picks the task up.

alter table public.execution_jobs drop constraint execution_jobs_kind_check;
alter table public.execution_jobs add constraint execution_jobs_kind_check
  check (kind in ('audit','source','monitor','dependency','graph','pr-check','notification','repair','intelligence'));

create table public.intelligence_scan_jobs (
  job_id uuid primary key references public.execution_jobs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  scan text not null check (scan in ('deep','pr')),
  pull_request_number integer check (pull_request_number is null or pull_request_number > 0),
  head_sha text check (head_sha is null or head_sha ~ '^[a-f0-9]{40}$'),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check ((scan = 'pr') = (pull_request_number is not null and head_sha is not null))
);
alter table public.intelligence_scan_jobs enable row level security;
revoke all on public.intelligence_scan_jobs from public, anon, authenticated;
grant select, insert, update, delete on public.intelligence_scan_jobs to service_role;

-- Internal: one job plus its identity context, idempotent per key. Callable
-- only from the definer functions below.
create function public.enqueue_intelligence_scan_job(
  p_user uuid, p_repository uuid, p_scan text, p_pr integer, p_head text, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid; v_context public.intelligence_scan_jobs;
begin
  v_job := public.enqueue_execution_job(p_user, p_repository, 'intelligence', p_key);
  select * into v_context from public.intelligence_scan_jobs where job_id = v_job;
  if found then
    if v_context.user_id <> p_user or v_context.repository_id <> p_repository or v_context.scan <> p_scan
      or v_context.pull_request_number is distinct from p_pr or v_context.head_sha is distinct from p_head then
      raise exception 'idempotency context mismatch';
    end if;
    return v_job;
  end if;
  insert into public.intelligence_scan_jobs(job_id, user_id, repository_id, scan, pull_request_number, head_sha)
    values (v_job, p_user, p_repository, p_scan, p_pr, p_head);
  return v_job;
end $$;

-- Daily admission: weekly deep scans (one per selected repository per ISO
-- week) and windowed PR scans (daily or every 2 days) for PRs whose
-- deterministic review landed inside the window, at their latest head.
create function public.enqueue_due_intelligence_scans(p_now timestamptz, p_limit integer default 100)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  candidate record; v_job uuid;
  eligible_count integer := 0; admitted_count integer := 0; failed_count integer := 0;
  v_week text; v_day date;
begin
  if p_now is null or p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid intelligence admission';
  end if;
  v_week := to_char(p_now at time zone 'UTC', 'IYYY-IW');
  v_day := (p_now at time zone 'UTC')::date;

  for candidate in
    select * from (
      select r.id as repository_id, r.user_id, 'deep'::text as scan, null::integer as pr, null::text as head,
        'intel-deep:' || r.id::text || ':' || v_week as key
      from public.repositories r
      join public.intelligence_connections c on c.user_id = r.user_id
      join public.user_profiles p on p.id = r.user_id
      where r.selected and c.revoked_at is null and c.deep_scan_cadence = 'weekly'
        and p.github_installation_id is not null
      union all
      select latest.repository_id, latest.user_id, 'pr', latest.pull_request_number, latest.head_sha,
        'intel-pr:' || latest.repository_id::text || ':' || latest.pull_request_number || ':' || latest.cadence || ':'
          || case latest.cadence when 'daily' then v_day::text
             else ((v_day - date '1970-01-01') / 2)::text end
      from (
        select distinct on (v.repository_id, v.pull_request_number)
          v.repository_id, v.user_id, v.pull_request_number, v.head_sha, c.pr_scan_cadence as cadence
        from public.pull_request_reviews v
        join public.repositories r on r.id = v.repository_id and r.user_id = v.user_id and r.selected
        join public.intelligence_connections c on c.user_id = v.user_id
        join public.user_profiles p on p.id = v.user_id
        where c.revoked_at is null and c.pr_scan_cadence in ('daily','every_2_days')
          and p.github_installation_id is not null and v.head_sha ~ '^[a-f0-9]{40}$'
          and v.checked_at <= p_now
          and v.checked_at > p_now - case c.pr_scan_cadence when 'daily' then interval '1 day' else interval '2 days' end
        order by v.repository_id, v.pull_request_number, v.checked_at desc
      ) latest
    ) due
    where not exists(select 1 from public.execution_jobs j
      where j.user_id = due.user_id and j.kind = 'intelligence' and j.deduplication_key = due.key)
    order by due.user_id, due.key
    limit p_limit
  loop
    eligible_count := eligible_count + 1;
    begin
      v_job := public.enqueue_intelligence_scan_job(candidate.user_id, candidate.repository_id,
        candidate.scan, candidate.pr, candidate.head, candidate.key);
      if v_job is null then failed_count := failed_count + 1; else admitted_count := admitted_count + 1; end if;
    exception when others then failed_count := failed_count + 1;
    end;
  end loop;
  return jsonb_build_object('eligible', eligible_count, 'admitted', admitted_count,
    'failed', failed_count, 'limited', eligible_count = p_limit);
end $$;

-- Every-PR cadence: called after the deterministic PR check. Returns null,
-- without queuing, unless the account currently approves every-PR scans.
create function public.enqueue_pull_request_intelligence(p_user uuid, p_repository uuid, p_pr integer, p_head text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_pr is null or p_pr <= 0 or p_head is null or p_head !~ '^[a-f0-9]{40}$' then
    raise exception 'invalid pull request context';
  end if;
  if not exists(select 1 from public.intelligence_connections
      where user_id = p_user and revoked_at is null and pr_scan_cadence = 'every_pr') then
    return null;
  end if;
  return public.enqueue_intelligence_scan_job(p_user, p_repository, 'pr', p_pr, p_head,
    'intel-pr:' || p_repository::text || ':' || p_pr || ':' || p_head);
end $$;

revoke all on function public.enqueue_intelligence_scan_job(uuid,uuid,text,integer,text,text) from public, anon, authenticated, service_role;
revoke all on function public.enqueue_due_intelligence_scans(timestamptz,integer) from public, anon, authenticated;
grant execute on function public.enqueue_due_intelligence_scans(timestamptz,integer) to service_role;
revoke all on function public.enqueue_pull_request_intelligence(uuid,uuid,integer,text) from public, anon, authenticated;
grant execute on function public.enqueue_pull_request_intelligence(uuid,uuid,integer,text) to service_role;

-- Paid alerts for risky pull requests (Step 9A). When a stored PR review
-- blocks, the same fenced transaction that stores it admits one durable
-- notification job for that PR head. Whether an email is sent is decided by
-- the notification worker: only when alerts are enabled and the account is
-- paid (AGENTS.md: meaningful-change email is paid only; free sees the GitHub
-- check and the dashboard).

create table public.pull_request_notifications (
  job_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  review_id uuid not null unique references public.pull_request_reviews(id) on delete cascade,
  created_at timestamptz not null default now(),
  foreign key (job_id, user_id) references public.execution_jobs(id, user_id) on delete cascade
);
alter table public.pull_request_notifications enable row level security;
revoke all on public.pull_request_notifications from public, anon, authenticated;
grant select, insert, update, delete on public.pull_request_notifications to service_role;

create or replace function public.persist_pull_request_review(p_user uuid, p_job uuid, p_token uuid, p_review jsonb)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  context public.pull_request_jobs;
  v_review_id uuid;
  notification_job uuid;
begin
  if p_review is null or jsonb_typeof(p_review) <> 'object' or pg_column_size(p_review) > 524288
    or jsonb_typeof(p_review->'findings') is distinct from 'array'
    or jsonb_array_length(p_review->'findings') > 100
    or p_review->>'verdict' not in ('pass','warn','block')
    or jsonb_typeof(p_review->'coverageComplete') is distinct from 'boolean' then
    raise exception 'invalid pull request review';
  end if;
  if exists(select 1 from jsonb_to_recordset(p_review->'findings') as f(
      id text, severity text, title text, detail text, file text, evidence text)
    where f.id is null or length(f.id) not between 1 and 400
      or f.severity not in ('CRITICAL','WARNING')
      or f.title is null or length(f.title) not between 1 and 1000
      or f.detail is null or length(f.detail) > 20000
      or f.file is null or length(f.file) not between 1 and 1000
      or f.evidence is null or length(f.evidence) > 20000) then
    raise exception 'invalid pull request finding';
  end if;

  select * into job from public.execution_jobs where id = p_job for update;
  if not found or job.user_id <> p_user or job.kind <> 'pr-check' or job.status <> 'running'
    or job.lease_token is distinct from p_token or job.lease_until <= now() then
    raise exception 'pull request check lease unavailable';
  end if;
  select * into context from public.pull_request_jobs where job_id = p_job;
  if not found or context.user_id <> p_user
    or (p_review->>'pullRequestNumber')::integer is distinct from context.pull_request_number
    or lower(p_review->>'headSha') is distinct from context.head_sha then
    raise exception 'pull request context mismatch';
  end if;
  if not exists(select 1 from public.repositories
      where id = context.repository_id and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;

  insert into public.pull_request_reviews(user_id, repository_id, pull_request_number, head_sha, head_ref,
      head_repository, same_repository, title, url, verdict, coverage_complete, findings)
    values (p_user, context.repository_id, context.pull_request_number, context.head_sha,
      nullif(p_review->>'headRef',''), nullif(p_review->>'headRepository',''),
      (p_review->>'sameRepository')::boolean, nullif(p_review->>'title',''), nullif(p_review->>'url',''),
      p_review->>'verdict', (p_review->>'coverageComplete')::boolean, p_review->'findings')
    on conflict (user_id, repository_id, pull_request_number, head_sha) do update set
      head_ref = excluded.head_ref, head_repository = excluded.head_repository,
      same_repository = excluded.same_repository, title = excluded.title, url = excluded.url,
      verdict = excluded.verdict, coverage_complete = excluded.coverage_complete,
      findings = excluded.findings, checked_at = now()
    returning id into v_review_id;

  -- A pull request that blocks earns one alert per head commit. Enqueued in
  -- this fenced transaction, so a retry or duplicate webhook cannot add a
  -- second; the notification worker decides whether this account gets email.
  if p_review->>'verdict' = 'block'
    and not exists(select 1 from public.pull_request_notifications where review_id = v_review_id) then
    notification_job := public.enqueue_execution_job(p_user, null, 'notification', 'pr-alert:' || v_review_id::text);
    insert into public.pull_request_notifications(job_id, user_id, review_id)
      values (notification_job, p_user, v_review_id) on conflict (review_id) do nothing;
  end if;
  return v_review_id;
end $$;

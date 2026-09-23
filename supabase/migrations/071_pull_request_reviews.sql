-- Stored pull-request reviews (Step 8B-1). The PR check used to exist only as
-- a GitHub check run, so the dashboard could not show what a PR introduced,
-- an alert could not link to it, and a fix could not target the PR's branch.
-- One row per selected repository, PR, and head commit, written only by the
-- PR-check worker holding that exact job's live lease.

create table public.pull_request_reviews (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  pull_request_number integer not null check (pull_request_number > 0),
  head_sha text not null check (head_sha ~ '^[a-f0-9]{7,64}$'),
  -- PR metadata read from GitHub at check time; null when it was unreadable.
  head_ref text check (head_ref is null or length(head_ref) between 1 and 255),
  head_repository text check (head_repository is null or head_repository ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  same_repository boolean,
  title text check (title is null or length(title) <= 500),
  url text check (url is null or url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+$'),
  verdict text not null check (verdict in ('pass','warn','block')),
  coverage_complete boolean not null,
  findings jsonb not null check (jsonb_typeof(findings) = 'array' and jsonb_array_length(findings) <= 100),
  checked_at timestamptz not null default now(),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  unique (user_id, repository_id, pull_request_number, head_sha)
);
create index pull_request_reviews_recent on public.pull_request_reviews(user_id, checked_at desc);
alter table public.pull_request_reviews enable row level security;
revoke all on public.pull_request_reviews from public, anon, authenticated;
grant select, insert, update, delete on public.pull_request_reviews to service_role;

create function public.persist_pull_request_review(p_user uuid, p_job uuid, p_token uuid, p_review jsonb)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  context public.pull_request_jobs;
  review_id uuid;
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
    returning id into review_id;
  return review_id;
end $$;

revoke all on function public.persist_pull_request_review(uuid,uuid,uuid,jsonb) from public, anon, authenticated;
grant execute on function public.persist_pull_request_review(uuid,uuid,uuid,jsonb) to service_role;

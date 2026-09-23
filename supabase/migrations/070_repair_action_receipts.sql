-- Clicked repairs as receipted, lease-fenced jobs (Step 3F-C2d / 8A).
-- Every branch/PR write needs its own customer click and an audit receipt
-- (AGENTS.md). The click used to open the PR inside the web request, leaving
-- no durable record of who asked, what was asked, or whether GitHub accepted
-- it. A click now creates one receipt and one identity-only repair job in the
-- same transaction; only the worker holding that job's live lease may record
-- the outcome. ShipLock still never merges or deploys.

alter table public.execution_jobs drop constraint execution_jobs_kind_check;
alter table public.execution_jobs add constraint execution_jobs_kind_check
  check (kind in ('audit','source','monitor','dependency','graph','pr-check','notification','repair'));

create table public.repair_action_receipts (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null unique,
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  -- risk-fix-pr: an agent finding from the Risks board; finding-fix-pr: a scan
  -- or provider finding from a fix card (may carry the customer's edit).
  action text not null check (action in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr')),
  finding_id text check (finding_id is null or length(finding_id) between 1 and 400),
  -- The customer's reviewed version of the fix, when they edited it. Authored
  -- by the customer; bounded like the request that carried it.
  edited_content text check (edited_content is null or length(edited_content) <= 60000),
  status text not null default 'queued'
    check (status in ('queued','opened','failed','uncertain')),
  pr_url text check (pr_url is null or pr_url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+$'),
  pr_number integer check (pr_number is null or pr_number > 0),
  failure_code text check (failure_code is null or failure_code in
    ('delivery_unconfirmed','github_rejected','finding_unavailable','repository_unavailable','not_fixable')),
  requested_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (job_id, user_id) references public.execution_jobs(id, user_id) on delete cascade,
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check ((action <> 'dependency-bump-pr') = (finding_id is not null)),
  check (action = 'finding-fix-pr' or edited_content is null),
  check ((status = 'opened') = (pr_url is not null and pr_number is not null)),
  check ((status in ('failed','uncertain')) = (failure_code is not null))
);
create index repair_action_receipts_user_idx on public.repair_action_receipts(user_id, requested_at desc);
alter table public.repair_action_receipts enable row level security;
revoke all on public.repair_action_receipts from public, anon, authenticated;
grant select, insert, update, delete on public.repair_action_receipts to service_role;

create function public.request_repair_action(
  p_user uuid, p_repository uuid, p_action text, p_finding text, p_edited text, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid; v_receipt public.repair_action_receipts;
begin
  if p_key is null or length(p_key) not between 1 and 200
    or p_action is null or p_action not in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr')
    or ((p_action <> 'dependency-bump-pr') <> (p_finding is not null))
    or (p_action <> 'finding-fix-pr' and p_edited is not null)
    or (p_finding is not null and length(p_finding) not between 1 and 400)
    or (p_edited is not null and length(p_edited) > 60000) then
    raise exception 'invalid repair request';
  end if;
  -- enqueue_execution_job refuses an unselected or foreign repository.
  v_job := public.enqueue_execution_job(p_user, p_repository, 'repair', 'repair:' || p_key);
  select * into v_receipt from public.repair_action_receipts where job_id = v_job;
  if found then
    if v_receipt.action <> p_action or v_receipt.finding_id is distinct from p_finding
      or v_receipt.edited_content is distinct from p_edited
      or v_receipt.repository_id <> p_repository then
      raise exception 'idempotency context mismatch';
    end if;
    return v_receipt.id;
  end if;
  insert into public.repair_action_receipts(job_id, user_id, repository_id, action, finding_id, edited_content)
    values (v_job, p_user, p_repository, p_action, p_finding, p_edited)
    returning * into v_receipt;
  return v_receipt.id;
end $$;

create function public.complete_repair_action(
  p_user uuid, p_job uuid, p_token uuid, p_status text, p_url text, p_number integer, p_failure text
)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
declare job public.execution_jobs;
begin
  if p_status is null or p_status not in ('opened','failed','uncertain') then
    raise exception 'invalid repair outcome';
  end if;
  select * into job from public.execution_jobs where id = p_job for update;
  if not found or job.user_id <> p_user or job.kind <> 'repair' or job.status <> 'running'
    or job.lease_token is distinct from p_token or job.lease_until <= now() then
    return false;
  end if;
  -- An opened PR is final. An uncertain delivery may later resolve to opened
  -- (the retry finds the PR by its deterministic branch) or to failed.
  update public.repair_action_receipts set
    status = p_status,
    pr_url = case when p_status = 'opened' then p_url end,
    pr_number = case when p_status = 'opened' then p_number end,
    failure_code = case when p_status = 'opened' then null else p_failure end,
    updated_at = now()
    where job_id = p_job and user_id = p_user and status in ('queued','uncertain');
  return found;
end $$;

revoke all on function public.request_repair_action(uuid,uuid,text,text,text,text) from public, anon, authenticated;
grant execute on function public.request_repair_action(uuid,uuid,text,text,text,text) to service_role;
revoke all on function public.complete_repair_action(uuid,uuid,uuid,text,text,integer,text) from public, anon, authenticated;
grant execute on function public.complete_repair_action(uuid,uuid,uuid,text,text,integer,text) to service_role;

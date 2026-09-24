-- Rate-limit suggestions as clicked repair PRs (Q12-3 / Step 11).
-- A new repair action, rate-limit-pr, admitted only when ShipLock has observed
-- traffic for that repository (086). finding_id carries 'traffic:<route file>'.
-- The worker re-derives the suggestion from current observations and the
-- repository tree, adds one new, off-by-default helper file on a new branch,
-- and opens the PR. Same receipt, quota, idempotency and one-click rules as
-- every other lane; ShipLock never merges.
alter table public.repair_action_receipts drop constraint repair_action_receipts_action_check;
alter table public.repair_action_receipts add constraint repair_action_receipts_action_check
  check (action in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr','pr-fix-pr','ai-fix-pr','rate-limit-pr'));

create or replace function public.request_repair_action(
  p_user uuid, p_repository uuid, p_action text, p_finding text, p_edited text, p_key text,
  p_review uuid default null, p_task uuid default null
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid; v_receipt public.repair_action_receipts; v_review public.pull_request_reviews;
  v_task public.intelligence_tasks;
begin
  if p_key is null or length(p_key) not between 1 and 200
    or p_action is null or p_action not in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr','pr-fix-pr','ai-fix-pr','rate-limit-pr')
    or ((p_action <> 'dependency-bump-pr') <> (p_finding is not null))
    or (p_action <> 'finding-fix-pr' and p_edited is not null)
    or ((p_action = 'pr-fix-pr') <> (p_review is not null))
    or ((p_action = 'ai-fix-pr') <> (p_task is not null))
    or (p_task is not null and p_finding is distinct from p_task::text)
    or (p_finding is not null and length(p_finding) not between 1 and 400)
    or (p_edited is not null and length(p_edited) > 60000)
    or ((p_action = 'rate-limit-pr') <> (p_finding is not null and p_finding ~ '^traffic:[^[:space:]]+$')) then
    raise exception 'invalid repair request';
  end if;
  -- A rate-limit PR needs observed traffic for this repository (Q12-3); the
  -- worker re-derives the route and the change from current evidence.
  if p_action = 'rate-limit-pr' and not exists(select 1 from public.traffic_route_observations o
      where o.user_id = p_user and o.repository_id = p_repository) then
    raise exception 'traffic evidence unavailable';
  end if;
  if p_review is not null then
    select * into v_review from public.pull_request_reviews where id = p_review;
    if not found or v_review.user_id <> p_user or v_review.repository_id <> p_repository
      or v_review.same_repository is not true or v_review.head_ref is null
      or not exists(select 1 from jsonb_array_elements(v_review.findings) f where f->>'id' = p_finding) then
      raise exception 'pull request review unavailable';
    end if;
  end if;
  if p_task is not null then
    select * into v_task from public.intelligence_tasks where id = p_task;
    if not found or v_task.user_id <> p_user or v_task.repository_id <> p_repository
      or v_task.status <> 'proposal_received'
      or jsonb_typeof(v_task.result->'edits') is distinct from 'array'
      or jsonb_array_length(v_task.result->'edits') = 0 then
      raise exception 'intelligence proposal unavailable';
    end if;
  end if;
  if not exists(select 1 from public.execution_jobs j
      where j.user_id = p_user and j.kind = 'repair' and j.deduplication_key = 'repair:' || p_key)
    and (select count(*) from public.repair_action_receipts r
      where r.user_id = p_user and r.requested_at > now() - interval '24 hours') >= 30 then
    raise exception 'repair quota reached';
  end if;
  -- enqueue_execution_job refuses an unselected or foreign repository.
  v_job := public.enqueue_execution_job(p_user, p_repository, 'repair', 'repair:' || p_key);
  select * into v_receipt from public.repair_action_receipts where job_id = v_job;
  if found then
    if v_receipt.action <> p_action or v_receipt.finding_id is distinct from p_finding
      or v_receipt.edited_content is distinct from p_edited
      or v_receipt.review_id is distinct from p_review
      or v_receipt.task_id is distinct from p_task
      or v_receipt.repository_id <> p_repository then
      raise exception 'idempotency context mismatch';
    end if;
    return v_receipt.id;
  end if;
  insert into public.repair_action_receipts(job_id, user_id, repository_id, action, finding_id, edited_content,
      review_id, task_id)
    values (v_job, p_user, p_repository, p_action, p_finding, p_edited, p_review, p_task)
    returning * into v_receipt;
  return v_receipt.id;
end $$;

revoke all on function public.request_repair_action(uuid,uuid,text,text,text,text,uuid,uuid) from public, anon, authenticated;
grant execute on function public.request_repair_action(uuid,uuid,text,text,text,text,uuid,uuid) to service_role;

-- Fix before merge (Step 8B-3). A customer who sees a risky pull request on
-- the dashboard can click once to have ShipLock open a fix PR into that pull
-- request's own head branch. The receipt is bound to the stored review
-- (migration 071), so the worker targets exactly the branch that was checked.
-- Fork pull requests are refused: ShipLock cannot push into a fork, and it
-- never falls back to a pull request against the default branch.

alter table public.repair_action_receipts
  add column review_id uuid references public.pull_request_reviews(id) on delete cascade;

alter table public.repair_action_receipts drop constraint repair_action_receipts_action_check;
alter table public.repair_action_receipts add constraint repair_action_receipts_action_check
  check (action in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr','pr-fix-pr'));
alter table public.repair_action_receipts
  add constraint repair_action_receipts_review_binding check ((action = 'pr-fix-pr') = (review_id is not null));

alter table public.repair_action_receipts drop constraint repair_action_receipts_failure_code_check;
alter table public.repair_action_receipts add constraint repair_action_receipts_failure_code_check
  check (failure_code is null or failure_code in ('delivery_unconfirmed','github_rejected','finding_unavailable',
    'repository_unavailable','not_fixable','no_changes','fork_pull_request','pull_request_closed'));

drop function public.request_repair_action(uuid,uuid,text,text,text,text);

create function public.request_repair_action(
  p_user uuid, p_repository uuid, p_action text, p_finding text, p_edited text, p_key text,
  p_review uuid default null
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid; v_receipt public.repair_action_receipts; v_review public.pull_request_reviews;
begin
  if p_key is null or length(p_key) not between 1 and 200
    or p_action is null or p_action not in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr','pr-fix-pr')
    or ((p_action <> 'dependency-bump-pr') <> (p_finding is not null))
    or (p_action <> 'finding-fix-pr' and p_edited is not null)
    or ((p_action = 'pr-fix-pr') <> (p_review is not null))
    or (p_finding is not null and length(p_finding) not between 1 and 400)
    or (p_edited is not null and length(p_edited) > 60000) then
    raise exception 'invalid repair request';
  end if;
  if p_review is not null then
    select * into v_review from public.pull_request_reviews where id = p_review;
    if not found or v_review.user_id <> p_user or v_review.repository_id <> p_repository
      or v_review.same_repository is not true or v_review.head_ref is null
      or not exists(select 1 from jsonb_array_elements(v_review.findings) f where f->>'id' = p_finding) then
      raise exception 'pull request review unavailable';
    end if;
  end if;
  -- enqueue_execution_job refuses an unselected or foreign repository.
  v_job := public.enqueue_execution_job(p_user, p_repository, 'repair', 'repair:' || p_key);
  select * into v_receipt from public.repair_action_receipts where job_id = v_job;
  if found then
    if v_receipt.action <> p_action or v_receipt.finding_id is distinct from p_finding
      or v_receipt.edited_content is distinct from p_edited
      or v_receipt.review_id is distinct from p_review
      or v_receipt.repository_id <> p_repository then
      raise exception 'idempotency context mismatch';
    end if;
    return v_receipt.id;
  end if;
  insert into public.repair_action_receipts(job_id, user_id, repository_id, action, finding_id, edited_content, review_id)
    values (v_job, p_user, p_repository, p_action, p_finding, p_edited, p_review)
    returning * into v_receipt;
  return v_receipt.id;
end $$;

revoke all on function public.request_repair_action(uuid,uuid,text,text,text,text,uuid) from public, anon, authenticated;
grant execute on function public.request_repair_action(uuid,uuid,text,text,text,text,uuid) to service_role;

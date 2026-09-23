-- Provisional caps on the remaining customer-click paths (Step 3H-2). Each was
-- deduplicated per minute or not at all, so one account could queue up to
-- 1,440 provider rechecks or repair PRs a day, or mint unlimited access tokens.
--   * manual provider rechecks: 20 per account per rolling 24 hours
--   * clicked repairs (each may open a GitHub PR): 30 per account per 24 hours
--   * active access tokens (PATs): 10 per account; revoked tokens do not count
-- The numbers are PROVISIONAL (AGENTS.md: quotas are measured and approved
-- before launch). A replay of an already-admitted click is never refused, and
-- scheduled, deploy, and hourly work is not counted.

create or replace function public.enqueue_monitoring_job(
  p_user uuid,p_trigger text,p_key text
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job_id uuid; existing_trigger text;
begin
  if p_trigger not in ('manual','deploy','hourly','scheduled_48h')
    or p_key is null or length(p_key) not between 1 and 256 then
    raise exception 'invalid monitoring context';
  end if;
  if not exists(select 1 from public.user_profiles p where p.id=p_user and (
      (p_trigger='hourly' and p.monitoring_enabled=true
        and nullif(btrim(p.monitored_project_url),'') is not null
        and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
      or (p_trigger in ('manual','deploy','scheduled_48h') and (
        (p.monitoring_enabled=true and nullif(btrim(p.monitored_project_url),'') is not null
          and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
        or nullif(btrim(p.postgres_dsn_encrypted),'') is not null
        or nullif(btrim(p.vercel_access_token_encrypted),'') is not null
        or (nullif(btrim(p.supabase_mgmt_token_encrypted),'') is not null
          and nullif(btrim(p.supabase_mgmt_project_ref),'') is not null)
        or (p.monitoring_enabled=true and nullif(btrim(p.monitored_app_url),'') is not null)))
    )) then raise exception 'monitoring unavailable'; end if;
  if p_trigger='manual'
    and not exists(select 1 from public.execution_jobs j
      where j.user_id=p_user and j.kind='monitor' and j.deduplication_key=p_key)
    and (select count(*) from public.monitoring_job_context c
      where c.user_id=p_user and c.trigger_source='manual' and c.created_at>now()-interval '24 hours') >= 20 then
    raise exception 'recheck quota reached';
  end if;
  v_job_id:=public.enqueue_execution_job(p_user,null,'monitor',p_key);
  insert into public.monitoring_job_context(job_id,user_id,trigger_source)
    values(v_job_id,p_user,p_trigger) on conflict(job_id) do nothing;
  select trigger_source into existing_trigger from public.monitoring_job_context where monitoring_job_context.job_id=v_job_id;
  if existing_trigger is distinct from p_trigger then raise exception 'idempotency context mismatch'; end if;
  return v_job_id;
end $$;

revoke all on function public.enqueue_monitoring_job(uuid,text,text) from public,anon,authenticated;
grant execute on function public.enqueue_monitoring_job(uuid,text,text) to service_role;

create or replace function public.request_repair_action(
  p_user uuid, p_repository uuid, p_action text, p_finding text, p_edited text, p_key text,
  p_review uuid default null, p_task uuid default null
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid; v_receipt public.repair_action_receipts; v_review public.pull_request_reviews;
  v_task public.intelligence_tasks;
begin
  if p_key is null or length(p_key) not between 1 and 200
    or p_action is null or p_action not in ('risk-fix-pr','finding-fix-pr','dependency-bump-pr','pr-fix-pr','ai-fix-pr')
    or ((p_action <> 'dependency-bump-pr') <> (p_finding is not null))
    or (p_action <> 'finding-fix-pr' and p_edited is not null)
    or ((p_action = 'pr-fix-pr') <> (p_review is not null))
    or ((p_action = 'ai-fix-pr') <> (p_task is not null))
    or (p_task is not null and p_finding is distinct from p_task::text)
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

create function public.enforce_api_token_limit()
returns trigger language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 7362));
  if (select count(*) from public.api_tokens where user_id = new.user_id and revoked_at is null) >= 10 then
    raise exception 'token limit reached';
  end if;
  return new;
end $$;
revoke all on function public.enforce_api_token_limit() from public, anon, authenticated;

create trigger api_tokens_limit before insert on public.api_tokens
  for each row execute function public.enforce_api_token_limit();

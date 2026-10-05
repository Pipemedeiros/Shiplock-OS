-- Audit reasoning on the customer's own agent (Felipe, 2026-10-01: ShipLock
-- makes no model call). After a complete audit, ShipLock asks the customer's
-- approved host to reason over the audit's route inventory (attack_reasoning).
-- Hypotheses that pass the deterministic guard become a second task
-- (attack_verification): the agent proves each one with quoted lines, ShipLock
-- re-reads those lines from GitHub, and only confirmed claims become findings,
-- here, atomically, for the newest complete audit of that repository. A stale,
-- malformed or unanswered task never creates or closes a finding. The task's
-- context is ShipLock's own observation (route facts, paths, tables, the
-- prompt), never customer source or a secret.

-- Tenant-bound foreign key target: a task names a run of the same tenant and
-- repository, never another tenant's.
alter table public.audit_runs add constraint audit_runs_id_user_repository_unique unique (id, user_id, repository_id);

alter table public.intelligence_tasks
  add column kind text not null default 'review'
    check (kind in ('review','attack_reasoning','attack_verification')),
  add column audit_run_id uuid,
  add column parent_task_id uuid references public.intelligence_tasks(id) on delete cascade,
  add column context jsonb
    check (context is null or (jsonb_typeof(context) = 'object' and pg_column_size(context) <= 262144)),
  add constraint intelligence_tasks_audit_run_fk foreign key (audit_run_id, user_id, repository_id)
    references public.audit_runs(id, user_id, repository_id) on delete cascade,
  add constraint intelligence_tasks_kind_shape check (
    (kind = 'review' and audit_run_id is null and parent_task_id is null and context is null)
    or (kind = 'attack_reasoning' and audit_run_id is not null and parent_task_id is null and context is not null)
    or (kind = 'attack_verification' and audit_run_id is not null and parent_task_id is not null and context is not null));
create index intelligence_tasks_audit_run on public.intelligence_tasks(audit_run_id) where audit_run_id is not null;

-- The customer API-key host is retired: no new approval may name it.
create or replace function public.approve_intelligence_connection(
  p_user uuid, p_host text, p_deep text, p_pr text, p_run integer, p_month integer
)
returns timestamptz language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_at timestamptz;
begin
  if p_host is null or p_host not in ('claude-code','codex','chatgpt') then
    raise exception 'invalid intelligence host';
  end if;
  insert into public.intelligence_connections(user_id, host, deep_scan_cadence, pr_scan_cadence,
      run_token_budget, monthly_token_budget)
    values (p_user, p_host, p_deep, p_pr, p_run, p_month)
  on conflict (user_id) do update set host = excluded.host,
    deep_scan_cadence = excluded.deep_scan_cadence, pr_scan_cadence = excluded.pr_scan_cadence,
    run_token_budget = excluded.run_token_budget, monthly_token_budget = excluded.monthly_token_budget,
    approved_at = now(), revoked_at = null, updated_at = now()
  returning approved_at into v_at;
  update public.intelligence_tasks set status = 'cancelled'
    where user_id = p_user and status = 'pending' and host <> p_host;
  return v_at;
end $$;

-- True when this run is complete and no later run of its repository has
-- completed: only the newest audit's reasoning may become findings.
create function public.audit_run_is_current(p_user uuid, p_run uuid)
returns boolean language sql stable security definer set search_path = pg_catalog, public as $$
  select exists(select 1 from public.audit_runs r where r.id = p_run and r.user_id = p_user and r.status = 'complete'
    and not exists(select 1 from public.audit_runs later where later.repository_id = r.repository_id
      and later.user_id = p_user and later.status = 'complete' and later.id <> r.id
      and later.finished_at > r.finished_at))
$$;

-- Turns a task just admitted by create_intelligence_task (validation,
-- approval, monthly budget, selected repository, installation binding) into a
-- reasoning or verification task, or confirms an idempotent replay.
create function public.shape_intelligence_task(
  p_task uuid, p_kind text, p_run uuid, p_parent uuid, p_context jsonb
)
returns void language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_task public.intelligence_tasks;
begin
  select * into v_task from public.intelligence_tasks where id = p_task for update;
  if v_task.kind = 'review' and v_task.status = 'pending' and v_task.context is null then
    update public.intelligence_tasks set kind = p_kind, audit_run_id = p_run, parent_task_id = p_parent, context = p_context
      where id = p_task;
  elsif v_task.kind <> p_kind or v_task.audit_run_id is distinct from p_run
    or v_task.parent_task_id is distinct from p_parent or v_task.context <> p_context then
    raise exception 'idempotency context mismatch';
  end if;
end $$;

create function public.create_audit_reasoning_task(
  p_user uuid, p_repository uuid, p_run uuid, p_commit text, p_host text, p_instruction text,
  p_sources jsonb, p_context jsonb, p_expires_at timestamptz, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_id uuid;
begin
  if p_context is null or jsonb_typeof(p_context) <> 'object' or p_key is null or p_key not like 'reason:%' then
    raise exception 'invalid intelligence task';
  end if;
  if not exists(select 1 from public.audit_runs where id = p_run and user_id = p_user and repository_id = p_repository
      and status = 'complete' and commit_sha = p_commit) then
    raise exception 'audit unavailable';
  end if;
  v_id := public.create_intelligence_task(p_user, p_repository, p_commit, p_host, p_instruction, p_sources, p_expires_at, p_key);
  perform public.shape_intelligence_task(v_id, 'attack_reasoning', p_run, null, p_context);
  -- A newer audit's reasoning supersedes any still pending for an older one.
  update public.intelligence_tasks set status = 'cancelled'
    where user_id = p_user and repository_id = p_repository and status = 'pending'
      and kind in ('attack_reasoning','attack_verification') and audit_run_id <> p_run;
  return v_id;
end $$;

create function public.create_verification_task(
  p_user uuid, p_parent uuid, p_instruction text, p_sources jsonb, p_context jsonb, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_parent public.intelligence_tasks; v_id uuid;
begin
  if p_context is null or jsonb_typeof(p_context) <> 'object' or p_key is null or p_key not like 'verify:%' then
    raise exception 'invalid intelligence task';
  end if;
  select * into v_parent from public.intelligence_tasks where id = p_parent and user_id = p_user for update;
  if not found or v_parent.kind <> 'attack_reasoning' or v_parent.status <> 'proposal_received' then
    raise exception 'parent unavailable';
  end if;
  if not public.audit_run_is_current(p_user, v_parent.audit_run_id) then raise exception 'task_stale'; end if;
  if not exists(select 1 from public.user_profiles where id = p_user
      and github_installation_id = v_parent.github_installation_id and github_connected_at = v_parent.github_connected_at) then
    raise exception 'task_scope_changed';
  end if;
  v_id := public.create_intelligence_task(p_user, v_parent.repository_id, v_parent.commit_sha, v_parent.host,
    p_instruction, p_sources, now() + interval '23 hours', p_key);
  perform public.shape_intelligence_task(v_id, 'attack_verification', v_parent.audit_run_id, p_parent, p_context);
  return v_id;
end $$;

-- Generic completion stays for review and reasoning tasks. A verification
-- task completes only through admit_verified_findings.
create or replace function public.submit_intelligence_result(
  p_user uuid, p_task uuid, p_status text, p_result jsonb, p_digest text
)
returns text language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_task public.intelligence_tasks;
begin
  if p_status is null or p_status not in ('proposal_received','needs_human','unavailable')
    or p_result is null or jsonb_typeof(p_result) <> 'object' or pg_column_size(p_result) > 65536
    or p_digest is null or p_digest !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid intelligence result';
  end if;
  select * into v_task from public.intelligence_tasks where id = p_task for update;
  if not found or v_task.user_id <> p_user or v_task.kind = 'attack_verification' then raise exception 'task unavailable'; end if;
  if v_task.result_digest is not null then
    if v_task.result_digest = p_digest then return 'replayed'; end if;
    raise exception 'already_completed';
  end if;
  if v_task.status <> 'pending' then raise exception 'task unavailable'; end if;
  if v_task.expires_at <= now() then raise exception 'task_expired'; end if;
  if not exists(select 1 from public.repositories
      where id = v_task.repository_id and user_id = p_user and selected = true)
    or not exists(select 1 from public.user_profiles where id = p_user
      and github_installation_id = v_task.github_installation_id
      and github_connected_at = v_task.github_connected_at) then
    raise exception 'task_scope_changed';
  end if;
  update public.intelligence_tasks set status = p_status, result = p_result, result_digest = p_digest,
    completed_at = now() where id = p_task;
  return 'accepted';
end $$;

-- Completes a verification task and admits its confirmed findings for the
-- task's audit run, in one transaction. Findings are only ever added: this
-- never archives one, so a missing or partial answer cannot close anything.
create function public.admit_verified_findings(
  p_user uuid, p_task uuid, p_status text, p_result jsonb, p_digest text, p_findings jsonb
)
returns text language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_task public.intelligence_tasks;
begin
  if p_status is null or p_status not in ('proposal_received','unavailable')
    or p_result is null or jsonb_typeof(p_result) <> 'object' or pg_column_size(p_result) > 65536
    or p_digest is null or p_digest !~ '^[a-f0-9]{64}$'
    or jsonb_typeof(p_findings) is distinct from 'array' or jsonb_array_length(p_findings) > 10
    or (p_status = 'unavailable' and jsonb_array_length(p_findings) > 0) then
    raise exception 'invalid intelligence result';
  end if;
  if exists(select 1 from jsonb_array_elements(p_findings) f
    where jsonb_typeof(f) is distinct from 'object' or coalesce(f->>'id','') not like 'agent:%'
      or length(f->>'id') > 2048 or coalesce(length(f->>'title'),0)=0
      or length(f->>'title') > 4096 or coalesce(length(f->>'consequence'),0)=0
      or length(f->>'consequence') > 20000
      or f->>'severity' not in ('CRITICAL','WARNING','INFO')
      or f->>'severity' is null or f->>'confidence' not in ('inferred','corroborated')
      or f->>'confidence' is null or f->>'fixKind' not in ('pr','one_click','manual')
      or f->>'fixKind' is null or jsonb_typeof(f->'claims') is distinct from 'array'
      or jsonb_array_length(f->'claims') > 100
      or exists(select 1 from jsonb_array_elements(f->'claims') claim
        where jsonb_typeof(claim) is distinct from 'object'
          or coalesce(length(claim->>'claim'),0)=0 or length(claim->>'claim') > 10000
          or claim->>'origin' not in ('routes','imports','schema','stack','secrets','live','agent')
          or jsonb_typeof(claim->'verified') is distinct from 'boolean'))
    then raise exception 'invalid finding'; end if;
  select * into v_task from public.intelligence_tasks where id = p_task for update;
  if not found or v_task.user_id <> p_user or v_task.kind <> 'attack_verification' then raise exception 'task unavailable'; end if;
  if v_task.result_digest is not null then
    if v_task.result_digest = p_digest then return 'replayed'; end if;
    raise exception 'already_completed';
  end if;
  if v_task.status <> 'pending' then raise exception 'task unavailable'; end if;
  if v_task.expires_at <= now() then raise exception 'task_expired'; end if;
  if not exists(select 1 from public.repositories
      where id = v_task.repository_id and user_id = p_user and selected = true)
    or not exists(select 1 from public.user_profiles where id = p_user
      and github_installation_id = v_task.github_installation_id
      and github_connected_at = v_task.github_connected_at) then
    raise exception 'task_scope_changed';
  end if;
  if not public.audit_run_is_current(p_user, v_task.audit_run_id) then raise exception 'task_stale'; end if;
  insert into public.deep_findings(user_id,repository_id,run_id,source,finding_id,severity,title,consequence,
    attack_class,entry,file,confidence,fix_kind,claims,blast_radius)
  select p_user,v_task.repository_id,v_task.audit_run_id,'agent',f->>'id',f->>'severity',f->>'title',f->>'consequence',
    f->>'attackClass',f->>'entry',f->>'file',f->>'confidence',f->>'fixKind',f->'claims',f->>'blastRadius'
    from jsonb_array_elements(p_findings) f
  on conflict (user_id,source,repository_id,finding_id)
    where archived_at is null and repository_id is not null do nothing;
  update public.intelligence_tasks set status = p_status, result = p_result, result_digest = p_digest,
    completed_at = now() where id = p_task;
  return 'accepted';
end $$;

revoke all on function public.approve_intelligence_connection(uuid,text,text,text,integer,integer) from public, anon, authenticated;
grant execute on function public.approve_intelligence_connection(uuid,text,text,text,integer,integer) to service_role;
revoke all on function public.audit_run_is_current(uuid,uuid) from public, anon, authenticated;
grant execute on function public.audit_run_is_current(uuid,uuid) to service_role;
revoke all on function public.shape_intelligence_task(uuid,text,uuid,uuid,jsonb) from public, anon, authenticated;
revoke all on function public.create_audit_reasoning_task(uuid,uuid,uuid,text,text,text,jsonb,jsonb,timestamptz,text) from public, anon, authenticated;
grant execute on function public.create_audit_reasoning_task(uuid,uuid,uuid,text,text,text,jsonb,jsonb,timestamptz,text) to service_role;
revoke all on function public.create_verification_task(uuid,uuid,text,jsonb,jsonb,text) from public, anon, authenticated;
grant execute on function public.create_verification_task(uuid,uuid,text,jsonb,jsonb,text) to service_role;
revoke all on function public.submit_intelligence_result(uuid,uuid,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.submit_intelligence_result(uuid,uuid,text,jsonb,text) to service_role;
revoke all on function public.admit_verified_findings(uuid,uuid,text,jsonb,text,jsonb) from public, anon, authenticated;
grant execute on function public.admit_verified_findings(uuid,uuid,text,jsonb,text,jsonb) to service_role;

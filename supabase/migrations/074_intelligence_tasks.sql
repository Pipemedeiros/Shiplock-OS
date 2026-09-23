-- Durable customer-intelligence tasks (Step 10B-1). A task asks a customer's
-- own coding agent (or model credential) to reason about one selected
-- repository at one commit. It stores paths and source hashes, never customer
-- source: the agent reads its own checkout and ShipLock re-reads cited files
-- from GitHub at the pinned commit before accepting a result. A task is bound
-- to the GitHub installation it was created under, so a reinstall or a
-- deselected repository stops new results. Submission is time-boxed; reading
-- an accepted result is not. Results are proposals only: nothing here applies
-- a change, opens a PR, or funds a model call.

create table public.intelligence_tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  commit_sha text not null check (commit_sha ~ '^[a-f0-9]{40}$'),
  github_installation_id bigint not null,
  github_connected_at timestamptz not null,
  host text not null check (host in ('codex','claude-code','api')),
  instruction text not null check (length(instruction) between 1 and 2000),
  sources jsonb not null check (jsonb_typeof(sources) = 'array' and jsonb_array_length(sources) between 1 and 16),
  idempotency_key text not null check (length(idempotency_key) between 1 and 200),
  status text not null default 'pending'
    check (status in ('pending','proposal_received','needs_human','unavailable','cancelled')),
  result jsonb check (result is null or pg_column_size(result) <= 65536),
  result_digest text check (result_digest is null or result_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  unique (user_id, idempotency_key),
  check ((status in ('proposal_received','needs_human','unavailable'))
    = (result is not null and result_digest is not null and completed_at is not null))
);
create index intelligence_tasks_recent on public.intelligence_tasks(user_id, created_at desc);
alter table public.intelligence_tasks enable row level security;
revoke all on public.intelligence_tasks from public, anon, authenticated;
grant select, insert, update, delete on public.intelligence_tasks to service_role;

create function public.create_intelligence_task(
  p_user uuid, p_repository uuid, p_commit text, p_host text, p_instruction text,
  p_sources jsonb, p_expires_at timestamptz, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_task public.intelligence_tasks; v_installation bigint; v_connected timestamptz;
begin
  if p_commit is null or p_commit !~ '^[a-f0-9]{40}$'
    or p_host is null or p_host not in ('codex','claude-code','api')
    or p_instruction is null or length(p_instruction) not between 1 and 2000
    or p_key is null or length(p_key) not between 1 and 200
    or p_expires_at is null or p_expires_at <= now() + interval '1 minute'
    or p_expires_at > now() + interval '24 hours'
    or p_sources is null or jsonb_typeof(p_sources) <> 'array'
    or jsonb_array_length(p_sources) not between 1 and 16 then
    raise exception 'invalid intelligence task';
  end if;
  -- Relative, normalized paths only; one entry per path.
  if exists(select 1 from jsonb_to_recordset(p_sources) as s(path text, "sourceHash" text)
      where s.path is null or length(s.path) not between 1 and 240
        or s.path like '/%' or s.path like '%\%' or s.path ~ '[[:cntrl:]]'
        or s.path ~ '(^|/)\.{1,2}(/|$)' or s.path like '%//%' or s.path like '%/'
        or s."sourceHash" is null or s."sourceHash" !~ '^[a-f0-9]{64}$')
    or (select count(distinct s->>'path') from jsonb_array_elements(p_sources) s) <> jsonb_array_length(p_sources) then
    raise exception 'invalid intelligence source';
  end if;

  select * into v_task from public.intelligence_tasks where user_id = p_user and idempotency_key = p_key;
  if found then
    if v_task.repository_id <> p_repository or v_task.commit_sha <> p_commit or v_task.host <> p_host
      or v_task.instruction <> p_instruction or v_task.sources <> p_sources then
      raise exception 'idempotency context mismatch';
    end if;
    return v_task.id;
  end if;

  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  select github_installation_id, github_connected_at into v_installation, v_connected
    from public.user_profiles where id = p_user;
  if v_installation is null or v_connected is null then raise exception 'installation unavailable'; end if;

  insert into public.intelligence_tasks(user_id, repository_id, commit_sha, github_installation_id,
      github_connected_at, host, instruction, sources, idempotency_key, expires_at)
    values (p_user, p_repository, p_commit, v_installation, v_connected, p_host, p_instruction,
      p_sources, p_key, p_expires_at)
    returning * into v_task;
  return v_task.id;
end $$;

create function public.submit_intelligence_result(
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
  if not found or v_task.user_id <> p_user then raise exception 'task unavailable'; end if;
  -- A completed task answers an exact replay, even after expiry, and refuses
  -- anything different.
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

create function public.cancel_intelligence_task(p_user uuid, p_task uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.intelligence_tasks set status = 'cancelled'
    where id = p_task and user_id = p_user and status = 'pending';
  return found;
end $$;

revoke all on function public.create_intelligence_task(uuid,uuid,text,text,text,jsonb,timestamptz,text) from public, anon, authenticated;
grant execute on function public.create_intelligence_task(uuid,uuid,text,text,text,jsonb,timestamptz,text) to service_role;
revoke all on function public.submit_intelligence_result(uuid,uuid,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.submit_intelligence_result(uuid,uuid,text,jsonb,text) to service_role;
revoke all on function public.cancel_intelligence_task(uuid,uuid) from public, anon, authenticated;
grant execute on function public.cancel_intelligence_task(uuid,uuid) to service_role;

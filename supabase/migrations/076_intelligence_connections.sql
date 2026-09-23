-- Customer-intelligence connection and standing approval (Step 10B-2b). At
-- onboarding a customer names the host that supplies intelligence (Claude
-- Code, Codex, ChatGPT, or their own model API key) and pre-approves when
-- ShipLock may ask it for work: a weekly deep scan and a PR-scan cadence,
-- within per-run and monthly token budgets, returning proposals only. It is
-- one row per account. It never approves a branch/PR write: every PR still
-- needs its own customer click. For pull hosts the budgets are advisory (the
-- host spends its own allowance); only a ShipLock-run API-key mode can
-- enforce them. No credential is stored here. New tasks require an active
-- approval for their host; revoking, or approving another host, cancels
-- pending tasks.

create table public.intelligence_connections (
  user_id uuid primary key references auth.users(id) on delete cascade,
  host text not null check (host in ('claude-code','codex','chatgpt','api')),
  deep_scan_cadence text not null check (deep_scan_cadence in ('weekly','off')),
  pr_scan_cadence text not null
    check (pr_scan_cadence in ('every_pr','every_2_days','daily','per_deploy','off')),
  run_token_budget integer not null check (run_token_budget between 1000 and 1000000),
  monthly_token_budget integer not null check (monthly_token_budget between 1000 and 50000000),
  proposals_allowed boolean not null default true check (proposals_allowed),
  approved_at timestamptz not null default now(),
  revoked_at timestamptz,
  updated_at timestamptz not null default now(),
  check (monthly_token_budget >= run_token_budget)
);
alter table public.intelligence_connections enable row level security;
revoke all on public.intelligence_connections from public, anon, authenticated;
grant select, insert, update, delete on public.intelligence_connections to service_role;

-- A ChatGPT host can hold tasks like the other pull hosts.
alter table public.intelligence_tasks drop constraint intelligence_tasks_host_check;
alter table public.intelligence_tasks add constraint intelligence_tasks_host_check
  check (host in ('codex','claude-code','chatgpt','api'));

create or replace function public.create_intelligence_task(
  p_user uuid, p_repository uuid, p_commit text, p_host text, p_instruction text,
  p_sources jsonb, p_expires_at timestamptz, p_key text
)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_task public.intelligence_tasks; v_installation bigint; v_connected timestamptz;
begin
  if p_commit is null or p_commit !~ '^[a-f0-9]{40}$'
    or p_host is null or p_host not in ('codex','claude-code','chatgpt','api')
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

  -- New work only for the host the customer approved, while approved.
  if not exists(select 1 from public.intelligence_connections
      where user_id = p_user and host = p_host and revoked_at is null) then
    raise exception 'intelligence not approved';
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

create function public.approve_intelligence_connection(
  p_user uuid, p_host text, p_deep text, p_pr text, p_run integer, p_month integer
)
returns timestamptz language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_at timestamptz;
begin
  insert into public.intelligence_connections(user_id, host, deep_scan_cadence, pr_scan_cadence,
      run_token_budget, monthly_token_budget)
    values (p_user, p_host, p_deep, p_pr, p_run, p_month)
  on conflict (user_id) do update set host = excluded.host,
    deep_scan_cadence = excluded.deep_scan_cadence, pr_scan_cadence = excluded.pr_scan_cadence,
    run_token_budget = excluded.run_token_budget, monthly_token_budget = excluded.monthly_token_budget,
    approved_at = now(), revoked_at = null, updated_at = now()
  returning approved_at into v_at;
  -- A different host was approved: the old host's queued work is withdrawn.
  update public.intelligence_tasks set status = 'cancelled'
    where user_id = p_user and status = 'pending' and host <> p_host;
  return v_at;
end $$;

create function public.revoke_intelligence_connection(p_user uuid)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare cancelled integer;
begin
  update public.intelligence_connections set revoked_at = now(), updated_at = now()
    where user_id = p_user and revoked_at is null;
  update public.intelligence_tasks set status = 'cancelled'
    where user_id = p_user and status = 'pending';
  get diagnostics cancelled = row_count;
  return cancelled;
end $$;

revoke all on function public.approve_intelligence_connection(uuid,text,text,text,integer,integer) from public, anon, authenticated;
grant execute on function public.approve_intelligence_connection(uuid,text,text,text,integer,integer) to service_role;
revoke all on function public.revoke_intelligence_connection(uuid) from public, anon, authenticated;
grant execute on function public.revoke_intelligence_connection(uuid) to service_role;

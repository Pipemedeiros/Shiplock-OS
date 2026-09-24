-- Provider evidence snapshots (Step 5A-2).
-- A provider pass used to leave only derived state (graph facts, open
-- findings): nothing recorded when it read, under which connection, what it
-- could not read, or that it failed. Each pass now appends one bounded
-- snapshot row, inside the same fenced transaction as its facts and findings,
-- and a failed pass records its reason under the job's live lease. Rows hold
-- scope and identity only (a project ref, host or team id and the opaque
-- connection epoch), never a credential or an application value.
--
-- Direct Postgres findings also get their own source: both database
-- transports used to write source 'policy', so a customer with both connected
-- had each pass retire the other transport's findings.
create table public.provider_snapshots (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  job_id uuid,
  transport text not null check (transport in ('postgres-direct','supabase-management','vercel','app-surface')),
  scope text check (length(scope) between 1 and 256),
  connection_identity text check (length(connection_identity) between 1 and 2048),
  observed_at timestamptz not null default now(),
  completeness text not null check (completeness in ('complete','partial','failed')),
  unread text[] not null default '{}' check (cardinality(unread) <= 500),
  reason text check (reason ~ '^[a-z_]{1,64}$'),
  finding_count integer check (finding_count >= 0),
  check ((completeness = 'failed') = (reason is not null))
);
create index provider_snapshots_latest_idx on public.provider_snapshots (user_id, transport, observed_at desc, id desc);
alter table public.provider_snapshots enable row level security;
revoke all on public.provider_snapshots from public, anon, authenticated;
grant select, insert, delete on public.provider_snapshots to service_role;

drop function public.persist_provider_monitor_result(uuid,uuid,uuid,text,text,jsonb,jsonb,boolean,jsonb);

create function public.persist_provider_monitor_result(
  p_user uuid,
  p_job uuid,
  p_token uuid,
  p_transport text,
  p_identity text,
  p_facts jsonb,
  p_findings jsonb,
  p_retire boolean,
  p_unread jsonb,
  p_snapshot jsonb
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  profile public.user_profiles;
  current_identity text;
  finding_source text;
  fact_collector text;
  previous jsonb;
  metadata jsonb;
  fact_key text;
  recorded text := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  created jsonb := '[]'::jsonb;
  item record;
  v_scope text;
  v_failed text[];
begin
  if p_transport not in ('postgres-direct','supabase-management','vercel','app-surface') then
    raise exception 'invalid provider transport';
  end if;
  -- Direct Postgres has its own source: a customer may connect both databases,
  -- and one transport must never retire or disconnect the other's findings.
  finding_source := case p_transport when 'vercel' then 'vercel'
    when 'app-surface' then 'exposed-path' when 'postgres-direct' then 'postgres-direct' else 'policy' end;
  fact_collector := case p_transport when 'vercel' then 'runtime'
    when 'app-surface' then null else 'db' end;

  if p_findings is null or jsonb_typeof(p_findings)<>'array' or jsonb_array_length(p_findings)>500
    or pg_column_size(p_findings)>1048576
    or p_unread is null or jsonb_typeof(p_unread)<>'array' or jsonb_array_length(p_unread)>500
    or (p_facts is not null and (jsonb_typeof(p_facts)<>'object' or pg_column_size(p_facts)>2097152
      or fact_collector is null or p_facts ? '_evidence'))
    or p_identity is null or length(p_identity) not between 1 and 2048 then
    raise exception 'invalid provider result payload';
  end if;
  if p_snapshot is null or jsonb_typeof(p_snapshot)<>'object'
    or (p_snapshot ? 'scope' and jsonb_typeof(p_snapshot->'scope') not in ('string','null'))
    or length(p_snapshot->>'scope') > 256
    or jsonb_typeof(p_snapshot->'failed')<>'array' or jsonb_array_length(p_snapshot->'failed')>500
    or exists(select 1 from jsonb_array_elements(p_snapshot->'failed') prefix
      where jsonb_typeof(prefix)<>'string' or length(prefix #>> '{}') not between 1 and 1000) then
    raise exception 'invalid provider snapshot';
  end if;
  v_scope := nullif(p_snapshot->>'scope', '');
  v_failed := array(select jsonb_array_elements_text(p_snapshot->'failed'));
  if exists(select 1 from jsonb_array_elements(p_unread) prefix
    where jsonb_typeof(prefix)<>'string' or length(prefix #>> '{}') not between 1 and 1000) then
    raise exception 'invalid unread prefix';
  end if;
  if exists(select 1 from jsonb_to_recordset(p_findings) as f(
      id text, severity text, title text, consequence text)
    where f.id is null or length(f.id) not between 1 and 1000
      or f.severity not in ('CRITICAL','WARNING','INFO')
      or f.title is null or length(f.title) not between 1 and 1000
      or f.consequence is null or length(f.consequence) not between 1 and 20000) then
    raise exception 'invalid provider finding';
  end if;

  select * into job from public.execution_jobs where id=p_job for update;
  if not found or job.user_id<>p_user or job.kind<>'monitor' or job.status<>'running'
    or job.lease_token is distinct from p_token or job.lease_until<=now() then
    raise exception 'monitor lease unavailable';
  end if;

  -- Lock the profile so a concurrent reconnect/disconnect serializes with us.
  select * into profile from public.user_profiles where id=p_user for update;
  if not found then raise exception 'profile unavailable'; end if;
  current_identity := case p_transport
    when 'postgres-direct' then profile.postgres_connection_epoch
    when 'supabase-management' then profile.supabase_mgmt_connection_epoch
    when 'vercel' then profile.vercel_connection_epoch
    else profile.monitored_app_url end;
  if current_identity is distinct from p_identity then
    raise exception 'provider connection changed';
  end if;

  if p_facts is not null then
    select facts into previous from public.graph_facts
      where user_id=p_user and collector=fact_collector for update;
    previous := coalesce(previous, '{}'::jsonb);
    metadata := case when previous->'_evidence'->>'version'='1'
      and jsonb_typeof(previous->'_evidence'->'fields')='object'
      then previous->'_evidence' else '{"version":1,"fields":{}}'::jsonb end;
    for fact_key in select jsonb_object_keys(p_facts) loop
      metadata := jsonb_set(metadata, array['fields', fact_key],
        jsonb_build_object('recordedAt', recorded, 'completeness', 'unknown'));
    end loop;
    insert into public.graph_facts(user_id, collector, facts, updated_at)
      values (p_user, fact_collector, (previous || p_facts) || jsonb_build_object('_evidence', metadata), now())
      on conflict (user_id, collector) do update
        set facts = excluded.facts, updated_at = excluded.updated_at;
  end if;

  if p_retire then
    update public.deep_findings existing set archived_at = now()
      where existing.user_id=p_user and existing.source=finding_source
        and existing.repository_id is null and existing.archived_at is null
        and not exists(select 1 from jsonb_to_recordset(p_findings) as f(id text) where f.id=existing.finding_id)
        and not exists(select 1 from jsonb_array_elements_text(p_unread) prefix
          where left(existing.finding_id, length(prefix))=prefix);
  end if;

  for item in select * from jsonb_to_recordset(p_findings) as f(
      id text, severity text, title text, consequence text,
      "packageName" text, version text, "vulnId" text, "cveId" text) loop
    if not exists(select 1 from public.deep_findings existing
        where existing.user_id=p_user and existing.source=finding_source
          and existing.repository_id is null and existing.archived_at is null
          and existing.finding_id=item.id) then
      insert into public.deep_findings(user_id, source, finding_id, severity, title, consequence,
          package_name, version, vuln_id, cve_id)
        values (p_user, finding_source, item.id, item.severity, item.title, item.consequence,
          item."packageName", item.version, item."vulnId", item."cveId");
      created := created || jsonb_build_object('id', item.id, 'severity', item.severity,
        'title', item.title, 'consequence', item.consequence);
    end if;
  end loop;

  insert into public.provider_snapshots(user_id, job_id, transport, scope, connection_identity,
      completeness, unread, finding_count)
    values (p_user, p_job, p_transport, v_scope, p_identity,
      case when cardinality(v_failed)=0 then 'complete' else 'partial' end, v_failed,
      jsonb_array_length(p_findings));

  return created;
end $$;

revoke all on function public.persist_provider_monitor_result(uuid,uuid,uuid,text,text,jsonb,jsonb,boolean,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.persist_provider_monitor_result(uuid,uuid,uuid,text,text,jsonb,jsonb,boolean,jsonb,jsonb)
  to service_role;

-- A pass that read nothing usable (auth failure, provider error, a fenced
-- commit) still leaves a record, so Coverage can say "last read failed".
create function public.record_provider_read_failure(
  p_user uuid, p_job uuid, p_token uuid, p_transport text, p_scope text, p_reason text
) returns void language plpgsql security definer set search_path = pg_catalog, public as $$
declare job public.execution_jobs;
begin
  if p_transport not in ('postgres-direct','supabase-management','vercel','app-surface') then
    raise exception 'invalid provider transport';
  end if;
  if p_reason is null or p_reason !~ '^[a-z_]{1,64}$' or length(p_scope) > 256 then
    raise exception 'invalid provider failure';
  end if;
  select * into job from public.execution_jobs where id=p_job;
  if not found or job.user_id<>p_user or job.kind<>'monitor' or job.status<>'running'
    or job.lease_token is distinct from p_token or job.lease_until<=now() then
    raise exception 'monitor lease unavailable';
  end if;
  insert into public.provider_snapshots(user_id, job_id, transport, scope, completeness, reason)
    values (p_user, p_job, p_transport, nullif(p_scope, ''), 'failed', p_reason);
end $$;

-- Keep 30 days, and always the latest snapshot per account and transport so
-- a quiet connection still shows when it was last read.
create function public.prune_provider_snapshots() returns integer
language plpgsql security definer set search_path = pg_catalog, public as $$
declare removed integer;
begin
  delete from public.provider_snapshots old
    where old.observed_at < now() - interval '30 days'
      and exists(select 1 from public.provider_snapshots newer
        where newer.user_id=old.user_id and newer.transport=old.transport
          and (newer.observed_at, newer.id) > (old.observed_at, old.id));
  get diagnostics removed = row_count;
  return removed;
end $$;

revoke all on function public.record_provider_read_failure(uuid,uuid,uuid,text,text,text) from public, anon, authenticated;
grant execute on function public.record_provider_read_failure(uuid,uuid,uuid,text,text,text) to service_role;
revoke all on function public.prune_provider_snapshots() from public, anon, authenticated;
grant execute on function public.prune_provider_snapshots() to service_role;

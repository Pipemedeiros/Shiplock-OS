-- Fenced provider monitoring results (Step 3F-C2c-1).
-- Provider collectors used to write graph facts and deep_findings through
-- separate calls, outside the monitor job's lease, and keyed on whatever
-- connection happened to be current at write time. This commits one
-- transport's result in a single transaction, and only while the collecting
-- monitor job still holds its lease and the transport's connection identity
-- (migration 067 epoch, or the app URL for app-surface probes) is unchanged.
-- Returns the findings that were newly inserted, so alerts derive from the
-- committed state rather than a separate read.

create function public.persist_provider_monitor_result(
  p_user uuid,
  p_job uuid,
  p_token uuid,
  p_transport text,
  p_identity text,
  p_facts jsonb,
  p_findings jsonb,
  p_retire boolean,
  p_unread jsonb
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
begin
  if p_transport not in ('postgres-direct','supabase-management','vercel','app-surface') then
    raise exception 'invalid provider transport';
  end if;
  finding_source := case p_transport when 'vercel' then 'vercel'
    when 'app-surface' then 'exposed-path' else 'policy' end;
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

  return created;
end $$;

revoke all on function public.persist_provider_monitor_result(uuid,uuid,uuid,text,text,jsonb,jsonb,boolean,jsonb)
  from public, anon, authenticated;
grant execute on function public.persist_provider_monitor_result(uuid,uuid,uuid,text,text,jsonb,jsonb,boolean,jsonb)
  to service_role;

-- The outside view, bound (P5, 2026-10-17). The app-surface pass already
-- downloads the scripts the founder's live site serves; it now also keeps the
-- paths that JavaScript calls, as a runtime fact under its own key, committed
-- in the same fenced transaction as its findings. Such a fact reaches a
-- repository's evidence only through a binding the founder confirmed: the
-- repository the address belongs to, and the address it was confirmed for.
-- Any other writer that changes the address leaves the bound address behind,
-- so the join stops on its own (AGENTS.md: a join needs the selected
-- repository, a current connection and a customer confirmation).
alter table public.user_profiles
  add column monitored_app_repository_id uuid,
  add column monitored_app_bound_url text check (length(monitored_app_bound_url) between 1 and 2048),
  add constraint user_profiles_app_repository_fk foreign key (monitored_app_repository_id, id)
    references public.repositories(id, user_id) on delete set null (monitored_app_repository_id),
  add constraint user_profiles_app_binding_pair check (monitored_app_repository_id is null or monitored_app_bound_url is not null);

create or replace function public.persist_provider_monitor_result(
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
  -- The live site's paths share the runtime namespace with Vercel, so an
  -- app-surface result may write its own key and nothing else.
  fact_collector := case p_transport when 'vercel' then 'runtime'
    when 'app-surface' then 'runtime' else 'db' end;
  if p_transport = 'app-surface' and p_facts is not null
    and (case when jsonb_typeof(p_facts)='object'
      then exists(select 1 from jsonb_object_keys(p_facts) k where k<>'appSurface') else true end) then
    raise exception 'invalid provider result payload';
  end if;

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

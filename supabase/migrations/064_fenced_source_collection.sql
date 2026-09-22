-- Persist one repository source snapshot and its deterministic findings only
-- while the matching source job owns a current lease. Source coverage is
-- partial, so absence never archives an earlier finding.
alter table public.repositories
  add column if not exists last_source_scan_at timestamptz;

comment on column public.repositories.last_source_scan_at is
  'Last successful fenced source snapshot for this exact selected repository.';

-- A reconnect/reselection or provider identity/branch change invalidates the
-- previous freshness receipt. Stored snapshots are also rejected at read time;
-- this reset makes the scheduler reacquire evidence without waiting 48 hours.
create function public.reset_repository_source_freshness()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
  if (old.selected=false and new.selected=true)
    or old.github_repo_id is distinct from new.github_repo_id
    or old.default_branch is distinct from new.default_branch then
    new.last_source_scan_at:=null;
  end if;
  return new;
end $$;

create trigger repositories_reset_source_freshness
  before update on public.repositories
  for each row execute function public.reset_repository_source_freshness();

revoke all on function public.reset_repository_source_freshness()
  from public,anon,authenticated;

create function public.persist_repository_source(
  p_user uuid,
  p_repository uuid,
  p_job uuid,
  p_token uuid,
  p_snapshot jsonb,
  p_findings jsonb
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  repository public.repositories;
  installation bigint;
  previous jsonb := '{}'::jsonb;
  snapshots jsonb := '[]'::jsonb;
  flat_routes jsonb := '[]'::jsonb;
  flat_dependencies jsonb := '[]'::jsonb;
  flat_live_files jsonb := '[]'::jsonb;
  next_facts jsonb;
  finding record;
  total_count integer := 0;
  new_count integer := 0;
  observed_at timestamptz;
begin
  if p_snapshot is null or jsonb_typeof(p_snapshot)<>'object'
    or p_findings is null or jsonb_typeof(p_findings)<>'array'
    or jsonb_array_length(p_findings)>500
    or pg_column_size(p_snapshot)>2097152 or pg_column_size(p_findings)>2097152 then
    raise exception 'invalid source payload';
  end if;

  begin
    observed_at := (p_snapshot->>'recordedAt')::timestamptz;
  exception when others then
    raise exception 'invalid source observation time';
  end;
  if observed_at > now() + interval '5 minutes' or observed_at < now() - interval '24 hours' then
    raise exception 'invalid source observation time';
  end if;

  select * into job from public.execution_jobs where id=p_job for update;
  if not found or job.user_id<>p_user or job.repository_id is distinct from p_repository
    or job.kind<>'source' or job.status<>'running' or job.lease_token is distinct from p_token
    or job.lease_until<=now() then raise exception 'source lease unavailable'; end if;

  select * into repository from public.repositories
    where id=p_repository and user_id=p_user and selected=true for update;
  if not found then raise exception 'repository unavailable'; end if;
  select github_installation_id into installation from public.user_profiles where id=p_user;
  if installation is null then raise exception 'installation unavailable'; end if;

  if p_snapshot->>'repositoryId' is distinct from p_repository::text
    or lower(p_snapshot->>'repositoryFullName') is distinct from lower(repository.full_name)
    or (repository.github_repo_id is not null and
      p_snapshot->>'providerRepositoryId' is distinct from repository.github_repo_id::text)
    or p_snapshot->>'installationId' is distinct from installation::text
    or p_snapshot->>'ref' is distinct from repository.default_branch
    or p_snapshot->>'completeness' is distinct from 'partial'
    or jsonb_typeof(p_snapshot->'filesAttempted') is distinct from 'number'
    or jsonb_typeof(p_snapshot->'filesRead') is distinct from 'number'
    or (p_snapshot->>'filesAttempted')::integer not between 0 and 60
    or (p_snapshot->>'filesRead')::integer not between 0 and 60
    or (p_snapshot->>'filesRead')::integer > (p_snapshot->>'filesAttempted')::integer
    or jsonb_typeof(p_snapshot->'hasEntryPoints') is distinct from 'boolean'
    or jsonb_typeof(p_snapshot->'routes') is distinct from 'array'
    or jsonb_typeof(p_snapshot->'liveFiles') is distinct from 'array'
    or jsonb_typeof(p_snapshot->'dependencies') is distinct from 'array'
    or jsonb_array_length(p_snapshot->'routes')>60
    or jsonb_array_length(p_snapshot->'liveFiles')>60
    or jsonb_array_length(p_snapshot->'dependencies')>5000 then
    raise exception 'source identity mismatch';
  end if;

  select facts into previous from public.graph_facts
    where user_id=p_user and collector='source' for update;
  previous := coalesce(previous,'{}'::jsonb);

  -- Retain only still-selected repository snapshots and replace this exact
  -- repository. Malformed legacy entries are dropped rather than chosen.
  select coalesce(jsonb_agg(entry),'[]'::jsonb) into snapshots
  from jsonb_array_elements(case when jsonb_typeof(previous->'repositories')='array'
    then previous->'repositories' else '[]'::jsonb end) entry
  where lower(entry->>'repositoryFullName')<>lower(repository.full_name)
    and exists(select 1 from public.repositories selected
      where selected.user_id=p_user and selected.selected=true
        and lower(selected.full_name)=lower(entry->>'repositoryFullName'));
  snapshots := snapshots || jsonb_build_array(p_snapshot);

  select coalesce(jsonb_agg(route),'[]'::jsonb) into flat_routes
    from jsonb_array_elements(snapshots) snapshot
    cross join lateral jsonb_array_elements(case when jsonb_typeof(snapshot->'routes')='array'
      then snapshot->'routes' else '[]'::jsonb end) route;
  select coalesce(jsonb_agg(dependency),'[]'::jsonb) into flat_dependencies
    from jsonb_array_elements(snapshots) snapshot
    cross join lateral jsonb_array_elements(case when jsonb_typeof(snapshot->'dependencies')='array'
      then snapshot->'dependencies' else '[]'::jsonb end) dependency;
  select coalesce(jsonb_agg(file),'[]'::jsonb) into flat_live_files
    from jsonb_array_elements(snapshots) snapshot
    cross join lateral jsonb_array_elements(case when jsonb_typeof(snapshot->'liveFiles')='array'
      then snapshot->'liveFiles' else '[]'::jsonb end) file;

  next_facts := previous || jsonb_build_object(
    'repositories',snapshots,
    'routes',flat_routes,
    'dependencies',flat_dependencies,
    'liveFiles',flat_live_files,
    'hasEntryPoints',exists(select 1 from jsonb_array_elements(snapshots) s where s->>'hasEntryPoints'='true'),
    '_evidence',jsonb_build_object('version',1,'fields',jsonb_build_object(
      'repositories',jsonb_build_object('recordedAt',p_snapshot->>'recordedAt','completeness','partial',
        'reason','Repository, file, and history limits prevent complete negative coverage.')
    ))
  );
  insert into public.graph_facts(user_id,collector,facts,updated_at)
    values(p_user,'source',next_facts,now())
    on conflict(user_id,collector) do update set facts=excluded.facts,updated_at=excluded.updated_at;

  for finding in select * from jsonb_to_recordset(p_findings) as value(
    finding_id text,severity text,title text,consequence text,
    package_name text,version text,vuln_id text,cve_id text
  ) loop
    total_count := total_count+1;
    if finding.finding_id is null or length(finding.finding_id) not between 1 and 1000
      or left(finding.finding_id,length(repository.full_name)+2) <> repository.full_name || '::'
      or finding.severity not in ('CRITICAL','WARNING','INFO')
      or finding.title is null or length(finding.title) not between 1 and 1000
      or finding.consequence is null or length(finding.consequence) not between 1 and 20000 then
      raise exception 'invalid source finding';
    end if;
    if not exists(select 1 from public.deep_findings d
      where d.user_id=p_user and d.repository_id=p_repository and d.source='github'
        and d.finding_id=finding.finding_id and d.archived_at is null) then
      insert into public.deep_findings(
        user_id,repository_id,source,finding_id,severity,title,consequence,
        package_name,version,vuln_id,cve_id
      ) values(
        p_user,p_repository,'github',finding.finding_id,finding.severity,finding.title,
        finding.consequence,finding.package_name,finding.version,finding.vuln_id,finding.cve_id
      );
      new_count := new_count+1;
    end if;
  end loop;

  -- Exact reproduced legacy rows migrate to repository scope. Missing rows are
  -- retained because the snapshot is partial.
  update public.deep_findings legacy set archived_at=now()
    where legacy.user_id=p_user and legacy.repository_id is null and legacy.source='github'
      and legacy.archived_at is null and exists(
        select 1 from jsonb_to_recordset(p_findings) as current(finding_id text)
        where current.finding_id=legacy.finding_id
      );
  update public.repositories set last_source_scan_at=now()
    where id=p_repository and user_id=p_user;
  -- Retained only for compatibility with older application builds. Repository
  -- scheduling and coalescing use the repository-local timestamp above.
  update public.user_profiles set last_source_scan_at=now() where id=p_user;
  return jsonb_build_object('total',total_count,'newCount',new_count,'resolvedCount',0);
end $$;

create function public.enqueue_due_repository_sources(
  p_cutoff timestamptz,
  p_day date,
  p_limit integer default 100
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare candidate record; job_id uuid; eligible_count integer:=0;
  admitted_count integer:=0; failed_count integer:=0;
begin
  if p_cutoff is null or p_day is null or p_limit is null or p_limit not between 1 and 5000
    then raise exception 'invalid source admission'; end if;
  for candidate in
    select r.id,r.user_id from public.repositories r
    join public.user_profiles p on p.id=r.user_id
    where r.selected=true and p.github_installation_id is not null
      and (r.last_source_scan_at is null or r.last_source_scan_at<p_cutoff)
      and not exists(select 1 from public.execution_jobs j
        where j.user_id=r.user_id and j.kind='source'
          and j.deduplication_key='scheduled-source:'||r.id::text||':'||p_day::text)
    order by r.last_source_scan_at asc nulls first,r.id limit p_limit
  loop
    eligible_count:=eligible_count+1;
    begin
      job_id:=public.enqueue_execution_job(candidate.user_id,candidate.id,'source',
        'scheduled-source:'||candidate.id::text||':'||p_day::text);
      if job_id is null then failed_count:=failed_count+1; else admitted_count:=admitted_count+1; end if;
    exception when others then failed_count:=failed_count+1;
    end;
  end loop;
  return jsonb_build_object('eligible',eligible_count,'admitted',admitted_count,
    'failed',failed_count,'limited',eligible_count=p_limit);
end $$;

-- The deterministic graph reasoner runs outside SQL, but its multi-row finding
-- replacement is accepted only from the currently leased graph attempt. The
-- caller may retire absent paths only when every required evidence surface was
-- readable; today's bounded source snapshots always pass false.
create function public.persist_repository_graph(
  p_user uuid,
  p_repository uuid,
  p_job uuid,
  p_token uuid,
  p_source_revision text,
  p_findings jsonb,
  p_allow_retire boolean default false
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  finding record;
  total_count integer := 0;
  new_count integer := 0;
  resolved_count integer := 0;
begin
  if p_source_revision is null or length(p_source_revision) not between 20 and 40
    or p_findings is null or jsonb_typeof(p_findings)<>'array'
    or jsonb_array_length(p_findings)>200 or pg_column_size(p_findings)>2097152
    or p_allow_retire is null then raise exception 'invalid graph payload'; end if;

  select * into job from public.execution_jobs where id=p_job for update;
  if not found or job.user_id<>p_user or job.repository_id is distinct from p_repository
    or job.kind<>'graph' or job.status<>'running' or job.lease_token is distinct from p_token
    or job.lease_until<=now() then raise exception 'graph lease unavailable'; end if;
  if not exists(select 1 from public.repositories
    where id=p_repository and user_id=p_user and selected=true for update)
    then raise exception 'repository unavailable'; end if;
  if not exists(
    select 1 from public.graph_facts facts
    cross join lateral jsonb_array_elements(case
      when jsonb_typeof(facts.facts->'repositories')='array'
      then facts.facts->'repositories' else '[]'::jsonb end) snapshot
    where facts.user_id=p_user and facts.collector='source'
      and snapshot->>'repositoryId'=p_repository::text
      and snapshot->>'recordedAt'=p_source_revision
  ) then raise exception 'source revision changed'; end if;

  for finding in select * from jsonb_to_recordset(p_findings) as value(
    finding_id text,severity text,title text,consequence text,surfaces jsonb
  ) loop
    total_count := total_count+1;
    if finding.finding_id is null or length(finding.finding_id) not between 1 and 1000
      or finding.severity not in ('CRITICAL','WARNING','INFO')
      or finding.title is null or length(finding.title) not between 1 and 1000
      or finding.consequence is null or length(finding.consequence) not between 1 and 20000
      or jsonb_typeof(finding.surfaces)<>'array'
      or jsonb_array_length(finding.surfaces) not between 2 and 5
      or (select count(distinct surface) from jsonb_array_elements_text(finding.surfaces) surface)<2
      or exists(select 1 from jsonb_array_elements_text(finding.surfaces) surface
        where surface not in ('source','db','config','traffic','runtime')) then
      raise exception 'invalid graph finding';
    end if;
    if not exists(select 1 from public.deep_findings d
      where d.user_id=p_user and d.repository_id=p_repository and d.source='graph'
        and d.finding_id=finding.finding_id and d.archived_at is null) then
      insert into public.deep_findings(
        user_id,repository_id,source,finding_id,severity,title,consequence,correlation
      ) values(
        p_user,p_repository,'graph',finding.finding_id,finding.severity,finding.title,
        finding.consequence,jsonb_build_object('surfaces',finding.surfaces,'proven',false)
      );
      new_count:=new_count+1;
    end if;
  end loop;

  if p_allow_retire then
    with retired as (
      update public.deep_findings existing set archived_at=now()
      where existing.user_id=p_user and existing.repository_id=p_repository
        and existing.source='graph' and existing.archived_at is null
        and not exists(select 1 from jsonb_to_recordset(p_findings) current(finding_id text)
          where current.finding_id=existing.finding_id)
      returning 1
    ) select count(*) into resolved_count from retired;
  end if;
  return jsonb_build_object('total',total_count,'newCount',new_count,
    'resolvedCount',resolved_count);
end $$;

revoke all on function public.persist_repository_source(uuid,uuid,uuid,uuid,jsonb,jsonb)
  from public,anon,authenticated;
revoke all on function public.enqueue_due_repository_sources(timestamptz,date,integer)
  from public,anon,authenticated;
revoke all on function public.persist_repository_graph(uuid,uuid,uuid,uuid,text,jsonb,boolean)
  from public,anon,authenticated;
grant execute on function public.persist_repository_source(uuid,uuid,uuid,uuid,jsonb,jsonb)
  to service_role;
grant execute on function public.enqueue_due_repository_sources(timestamptz,date,integer)
  to service_role;
grant execute on function public.persist_repository_graph(uuid,uuid,uuid,uuid,text,jsonb,boolean)
  to service_role;

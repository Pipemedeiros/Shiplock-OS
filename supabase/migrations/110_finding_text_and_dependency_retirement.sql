-- 110: a finding the scan reports again shows the scan's current words
-- (Felipe 2026-10-20). Persistence inserted a finding once and never touched
-- its text again, so copy fixed in code never reached a stored finding: on
-- 2026-10-20 all 30 open source findings on ShipLock's own repository still
-- carried wording from before the no-dash sweep, though every daily scan
-- reported them again. Same function and signature as 109, with one change:
-- an open row the scan reports again takes its title and consequence.
--
-- Dependency findings never retired (065: absence proves nothing), so a
-- package the founder upgraded stayed open. A lockfile read in full does
-- prove one thing: which versions it installs. The source snapshot now names
-- that lockfile; persist_repository_dependency_findings binds each finding to
-- it and retires a finding of that lockfile whose package and version are gone.
create or replace function public.persist_repository_source(
  p_user uuid,
  p_repository uuid,
  p_job uuid,
  p_token uuid,
  p_snapshot jsonb,
  p_findings jsonb,
  p_history_read text[] default '{}'
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
  resolved_count integer := 0;
  observed_at timestamptz;
begin
  if p_snapshot is null or jsonb_typeof(p_snapshot)<>'object'
    or p_findings is null or jsonb_typeof(p_findings)<>'array'
    or jsonb_array_length(p_findings)>500
    or pg_column_size(p_snapshot)>2097152 or pg_column_size(p_findings)>2097152 then
    raise exception 'invalid source payload';
  end if;
  if p_history_read is null or cardinality(p_history_read)>200
    or exists(select 1 from unnest(p_history_read) sha where sha is null or sha !~ '^[0-9a-f]{40}$') then
    raise exception 'invalid source history window';
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
    else
      -- 110: the open row takes the wording this scan wrote. Severity, first
      -- detection and open state are not text and stay as they were.
      update public.deep_findings d set title=finding.title, consequence=finding.consequence
        where d.user_id=p_user and d.repository_id=p_repository and d.source='github'
          and d.finding_id=finding.finding_id and d.archived_at is null
          and (d.title is distinct from finding.title or d.consequence is distinct from finding.consequence);
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
  -- 109: a history finding names the commit that added the secret. When this
  -- scan read that exact commit in full and no longer reports the finding,
  -- the earlier report was the scanner's mistake, so it retires. Any other
  -- class, and any commit outside the fully read window, stays open.
  with retired as (
    update public.deep_findings d set archived_at=now()
      where d.user_id=p_user and d.repository_id=p_repository and d.source='github'
        and d.archived_at is null
        and starts_with(d.finding_id, repository.full_name || '::github:history_secret:')
        and right(d.finding_id,12) in (select left(sha,12) from unnest(p_history_read) sha)
        and not exists(select 1 from jsonb_to_recordset(p_findings) as current(finding_id text)
          where current.finding_id=d.finding_id)
      returning 1
  ) select count(*) into resolved_count from retired;

  update public.repositories set last_source_scan_at=now()
    where id=p_repository and user_id=p_user;
  -- Retained only for compatibility with older application builds. Repository
  -- scheduling and coalescing use the repository-local timestamp above.
  update public.user_profiles set last_source_scan_at=now() where id=p_user;
  return jsonb_build_object('total',total_count,'newCount',new_count,'resolvedCount',resolved_count);
end $$;

revoke all on function public.persist_repository_source(uuid,uuid,uuid,uuid,jsonb,jsonb,text[])
  from public,anon,authenticated;
grant execute on function public.persist_repository_source(uuid,uuid,uuid,uuid,jsonb,jsonb,text[])
  to service_role;

create or replace function public.persist_repository_dependency_findings(
  p_user uuid,
  p_repository uuid,
  p_job uuid,
  p_token uuid,
  p_source_revision text,
  p_findings jsonb
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  job public.execution_jobs;
  repository public.repositories;
  profile public.user_profiles;
  finding record;
  total_count integer:=0;
  new_count integer:=0;
  resolved_count integer:=0;
  snapshot jsonb;
  lockfile text;
begin
  if p_source_revision is null or length(p_source_revision) not between 20 and 40
    or p_findings is null or jsonb_typeof(p_findings)<>'array'
    or jsonb_array_length(p_findings)>500 or pg_column_size(p_findings)>2097152
    then raise exception 'invalid dependency payload'; end if;

  select * into job from public.execution_jobs where id=p_job for update;
  if not found or job.user_id<>p_user or job.repository_id is distinct from p_repository
    or job.kind<>'dependency' or job.status<>'running'
    or job.lease_token is distinct from p_token or job.lease_until<=now()
    then raise exception 'dependency lease unavailable'; end if;
  select * into profile from public.user_profiles where id=p_user for update;
  if not found or profile.github_installation_id is null
    or profile.github_connected_at is null then
    raise exception 'installation unavailable';
  end if;
  -- Reconnect invalidation locks profile then repository through its trigger.
  -- Keep the same order here to avoid a profile↔repository deadlock.
  select * into repository from public.repositories
    where id=p_repository and user_id=p_user and selected=true for update;
  if not found then raise exception 'repository unavailable'; end if;

  select source_snapshot into snapshot from (select entry as source_snapshot from public.graph_facts facts
    cross join lateral jsonb_array_elements(case
      when jsonb_typeof(facts.facts->'repositories')='array'
      then facts.facts->'repositories' else '[]'::jsonb end) entry
    where facts.user_id=p_user and facts.collector='source'
      and entry->>'repositoryId'=p_repository::text
      and entry->>'recordedAt'=p_source_revision
      and lower(entry->>'repositoryFullName')=lower(repository.full_name)
      and entry->>'ref'=repository.default_branch
      and (repository.github_repo_id is null
        or entry->>'providerRepositoryId'=repository.github_repo_id::text)
      and entry->>'installationId'=profile.github_installation_id::text
      and (entry->>'recordedAt')::timestamptz>=profile.github_connected_at
      and repository.last_source_scan_at is not null
      and repository.last_source_scan_at>=(entry->>'recordedAt')::timestamptz
    limit 1) admitted;
  if snapshot is null then raise exception 'source revision changed'; end if;
  -- 110: the lockfile the inventory was read from, in full. Only a plain
  -- repository path counts; anything else is no lockfile.
  lockfile:=case when snapshot->>'lockfile' ~ '^([A-Za-z0-9_@][A-Za-z0-9._@-]*/)*package-lock\.json$'
    then snapshot->>'lockfile' end;

  for finding in select * from jsonb_to_recordset(p_findings) as value(
    finding_id text,severity text,title text,consequence text,
    package_name text,version text,vuln_id text,cve_id text
  ) loop
    total_count:=total_count+1;
    if finding.finding_id is null or length(finding.finding_id) not between 1 and 1000
      or left(finding.finding_id,length(repository.full_name)+2)<>repository.full_name||'::'
      or finding.severity not in ('CRITICAL','WARNING','INFO')
      or finding.title is null or length(finding.title) not between 1 and 1000
      or finding.consequence is null or length(finding.consequence) not between 1 and 20000
      then raise exception 'invalid dependency finding'; end if;
    if not exists(select 1 from public.deep_findings existing
      where existing.user_id=p_user and existing.repository_id=p_repository
        and existing.source in ('github','zero-day')
        and existing.finding_id=finding.finding_id and existing.archived_at is null) then
      insert into public.deep_findings(
        user_id,repository_id,source,finding_id,severity,title,consequence,
        package_name,version,vuln_id,cve_id,file
      ) values(
        p_user,p_repository,'zero-day',finding.finding_id,finding.severity,
        finding.title,finding.consequence,finding.package_name,finding.version,
        finding.vuln_id,finding.cve_id,lockfile
      );
      new_count:=new_count+1;
    else
      -- 110: reported again, so it takes this run's words and version and,
      -- when a lockfile was read, the lockfile it is now known to come from.
      update public.deep_findings existing set title=finding.title, consequence=finding.consequence,
          package_name=coalesce(finding.package_name,existing.package_name),
          version=coalesce(finding.version,existing.version), file=coalesce(lockfile,existing.file)
        where existing.user_id=p_user and existing.repository_id=p_repository
          and existing.source in ('github','zero-day')
          and existing.finding_id=finding.finding_id and existing.archived_at is null;
    end if;
  end loop;
  -- An advisory feed going quiet proves nothing. What can be proven is that
  -- a lockfile read in full no longer installs a version: a finding bound to
  -- that same lockfile, for a package and version it no longer holds, and not
  -- reported by this run, is fixed. Other lockfiles, unbound rows, and runs
  -- that read no lockfile retire nothing.
  if lockfile is not null then
    with retired as (
      update public.deep_findings d set archived_at=now()
        where d.user_id=p_user and d.repository_id=p_repository
          and d.source in ('github','zero-day') and d.archived_at is null
          and starts_with(d.finding_id, repository.full_name || '::github:dep:')
          and d.file=lockfile and d.package_name is not null and d.version is not null
          and not exists(select 1 from jsonb_array_elements(case when jsonb_typeof(snapshot->'dependencies')='array'
              then snapshot->'dependencies' else '[]'::jsonb end) installed
            where installed->>'name'=d.package_name and installed->>'version'=d.version)
          and not exists(select 1 from jsonb_to_recordset(p_findings) as current(finding_id text)
            where current.finding_id=d.finding_id)
        returning 1
    ) select count(*) into resolved_count from retired;
  end if;
  return jsonb_build_object('total',total_count,'newCount',new_count,'resolvedCount',resolved_count);
end $$;

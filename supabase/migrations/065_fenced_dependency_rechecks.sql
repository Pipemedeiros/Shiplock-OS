-- Daily advisory rechecks use the dependency inventory captured by the bounded
-- source collector. Jobs contain identities only; OSV results commit only while
-- the matching dependency lease and source revision remain current.
create function public.reset_repository_source_on_github_connection()
returns trigger language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if old.github_installation_id is distinct from new.github_installation_id
    or old.github_connected_at is distinct from new.github_connected_at then
    update public.repositories set last_source_scan_at=null where user_id=new.id;
  end if;
  return new;
end $$;

create trigger user_profiles_reset_repository_source_freshness
  after update of github_installation_id,github_connected_at on public.user_profiles
  for each row execute function public.reset_repository_source_on_github_connection();

revoke all on function public.reset_repository_source_on_github_connection()
  from public,anon,authenticated;

create function public.enqueue_due_repository_dependencies(
  p_day date,
  p_limit integer default 100
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  candidate record;
  job_id uuid;
  eligible_count integer:=0;
  admitted_count integer:=0;
  failed_count integer:=0;
begin
  if p_day is null or p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid dependency admission';
  end if;

  for candidate in
    select distinct r.id,r.user_id
    from public.repositories r
    join public.user_profiles p on p.id=r.user_id
    join public.graph_facts facts on facts.user_id=r.user_id and facts.collector='source'
    cross join lateral jsonb_array_elements(case
      when jsonb_typeof(facts.facts->'repositories')='array'
      then facts.facts->'repositories' else '[]'::jsonb end) snapshot
    where r.selected=true and r.last_source_scan_at is not null
      and p.github_installation_id is not null
      and snapshot->>'repositoryId'=r.id::text
      and jsonb_typeof(snapshot->'dependencies')='array'
      and jsonb_array_length(snapshot->'dependencies')>0
      and not exists(select 1 from public.execution_jobs j
        where j.user_id=r.user_id and j.kind='dependency'
          and j.deduplication_key='scheduled-dependency:'||r.id::text||':'||p_day::text)
    order by r.id
    limit p_limit
  loop
    eligible_count:=eligible_count+1;
    begin
      job_id:=public.enqueue_execution_job(candidate.user_id,candidate.id,'dependency',
        'scheduled-dependency:'||candidate.id::text||':'||p_day::text);
      if job_id is null then failed_count:=failed_count+1;
      else admitted_count:=admitted_count+1; end if;
    exception when others then failed_count:=failed_count+1;
    end;
  end loop;
  return jsonb_build_object('eligible',eligible_count,'admitted',admitted_count,
    'failed',failed_count,'limited',eligible_count=p_limit);
end $$;

create function public.persist_repository_dependency_findings(
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

  if not exists(
    select 1 from public.graph_facts facts
    cross join lateral jsonb_array_elements(case
      when jsonb_typeof(facts.facts->'repositories')='array'
      then facts.facts->'repositories' else '[]'::jsonb end) snapshot
    where facts.user_id=p_user and facts.collector='source'
      and snapshot->>'repositoryId'=p_repository::text
      and snapshot->>'recordedAt'=p_source_revision
      and lower(snapshot->>'repositoryFullName')=lower(repository.full_name)
      and snapshot->>'ref'=repository.default_branch
      and (repository.github_repo_id is null
        or snapshot->>'providerRepositoryId'=repository.github_repo_id::text)
      and snapshot->>'installationId'=profile.github_installation_id::text
      and (snapshot->>'recordedAt')::timestamptz>=profile.github_connected_at
      and repository.last_source_scan_at is not null
      and repository.last_source_scan_at>=(snapshot->>'recordedAt')::timestamptz
  ) then raise exception 'source revision changed'; end if;

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
        package_name,version,vuln_id,cve_id
      ) values(
        p_user,p_repository,'zero-day',finding.finding_id,finding.severity,
        finding.title,finding.consequence,finding.package_name,finding.version,
        finding.vuln_id,finding.cve_id
      );
      new_count:=new_count+1;
    end if;
  end loop;
  -- Inventories and advisory feeds are partial. Absence never proves a prior
  -- vulnerability fixed, so this RPC intentionally has no archival branch.
  return jsonb_build_object('total',total_count,'newCount',new_count,'resolvedCount',0);
end $$;

revoke all on function public.enqueue_due_repository_dependencies(date,integer)
  from public,anon,authenticated;
revoke all on function public.persist_repository_dependency_findings(uuid,uuid,uuid,uuid,text,jsonb)
  from public,anon,authenticated;
grant execute on function public.enqueue_due_repository_dependencies(date,integer)
  to service_role;
grant execute on function public.persist_repository_dependency_findings(uuid,uuid,uuid,uuid,text,jsonb)
  to service_role;

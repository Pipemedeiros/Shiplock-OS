-- PostgREST ON CONFLICT(column,...) cannot infer migration 051's partial
-- index without its predicate. Keep recurrence history and write atomically.
create function public.persist_repository_findings(
  p_user uuid, p_repository uuid, p_run uuid, p_findings jsonb, p_preserve boolean,
  p_job uuid default null, p_token uuid default null
) returns void language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_preserve is null or jsonb_typeof(p_findings) is distinct from 'array'
    or jsonb_array_length(p_findings)>10000 then raise exception 'invalid findings'; end if;
  perform 1 from public.repositories where id=p_repository and user_id=p_user and selected=true for update;
  if not found then raise exception 'repository unavailable'; end if;
  perform 1 from public.audit_runs where id=p_run and repository_id=p_repository and user_id=p_user and status='running' for update;
  if not found then raise exception 'run unavailable'; end if;
  if (p_job is null) <> (p_token is null) then raise exception 'invalid lease context'; end if;
  if p_job is not null and not exists(select 1 from public.execution_jobs
    where id=p_job and audit_run_id=p_run and user_id=p_user and repository_id=p_repository
      and status='running' and lease_token=p_token and lease_until>now())
    then raise exception 'work lease unavailable'; end if;
  if exists(select 1 from jsonb_array_elements(p_findings) f
    where jsonb_typeof(f) is distinct from 'object' or coalesce(length(f->>'id'),0)=0
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
  insert into public.deep_findings(user_id,repository_id,run_id,source,finding_id,severity,title,consequence,
    attack_class,entry,file,confidence,fix_kind,claims,blast_radius)
  select p_user,p_repository,p_run,'agent',f->>'id',f->>'severity',f->>'title',f->>'consequence',
    f->>'attackClass',f->>'entry',f->>'file',f->>'confidence',f->>'fixKind',f->'claims',f->>'blastRadius'
    from jsonb_array_elements(p_findings) f
  on conflict (user_id,source,repository_id,finding_id)
    where archived_at is null and repository_id is not null do nothing;
  if not p_preserve then
    update public.deep_findings set archived_at=now()
      where user_id=p_user and repository_id=p_repository and source='agent' and archived_at is null
      and not exists(select 1 from jsonb_array_elements(p_findings) f where f->>'id'=finding_id);
  end if;
end $$;
revoke all on function public.persist_repository_findings(uuid,uuid,uuid,jsonb,boolean,uuid,uuid) from public,anon,authenticated;
grant execute on function public.persist_repository_findings(uuid,uuid,uuid,jsonb,boolean,uuid,uuid) to service_role;

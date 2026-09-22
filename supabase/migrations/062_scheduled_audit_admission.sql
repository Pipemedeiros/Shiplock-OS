-- Set-based admission for stale selected repositories. The daily scheduler
-- does no repository/model work itself; it durably records bounded work before
-- starting legacy monitoring side effects. A day key makes cron retries
-- idempotent while allowing a failed/dead job to be retried the next day.
create function public.enqueue_due_repository_audits(
  p_cutoff timestamptz,
  p_day date,
  p_require_paid boolean default false,
  p_limit integer default 100
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare candidate record; receipt record; eligible_count integer := 0;
  admitted_count integer := 0; failed_count integer := 0;
begin
  if p_cutoff is null or p_day is null or p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid schedule admission';
  end if;

  for candidate in
    select r.id,r.user_id
    from public.repositories r
    join public.user_profiles p on p.id=r.user_id
    where r.selected=true and p.github_installation_id is not null
      and (r.last_audit_at is null or r.last_audit_at<p_cutoff)
      and (not p_require_paid or p.is_paid=true)
      and not exists (
        select 1 from public.execution_jobs j
        where j.user_id=r.user_id and j.kind='audit'
          and j.deduplication_key='scheduled:' || r.id::text || ':' || p_day::text
      )
    order by r.last_audit_at asc nulls first,r.id
    limit p_limit
  loop
    eligible_count := eligible_count + 1;
    begin
      select * into receipt from public.enqueue_repository_audit(
        candidate.user_id,
        candidate.id,
        'scheduled:' || candidate.id::text || ':' || p_day::text,
        'scheduled'
      );
      if receipt.job_id is null or receipt.run_id is null then
        failed_count := failed_count + 1;
      else
        admitted_count := admitted_count + 1;
      end if;
    exception when others then
      failed_count := failed_count + 1;
    end;
  end loop;

  return jsonb_build_object(
    'eligible',eligible_count,
    'admitted',admitted_count,
    'failed',failed_count,
    'limited',eligible_count=p_limit
  );
end $$;

revoke all on function public.enqueue_due_repository_audits(timestamptz,date,boolean,integer)
  from public,anon,authenticated;
grant execute on function public.enqueue_due_repository_audits(timestamptz,date,boolean,integer)
  to service_role;

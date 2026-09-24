-- Supabase gateway traffic reads as provider snapshots (Q8 / Step 2F-5b).
-- The no-install traffic read (2F-4, migration 086) only logged whether the
-- API gateway log was readable, so Coverage could not say "no traffic read".
-- Each read now appends a snapshot under the monitor job's live lease:
-- complete when the log was read, failed (log_unread) when it was not. The
-- scope is the Supabase project ref; paths and client identifiers stay out.
-- "Unbound" and "not enabled" are derived at render time, not stored.
alter table public.provider_snapshots drop constraint provider_snapshots_transport_check;
alter table public.provider_snapshots add constraint provider_snapshots_transport_check
  check (transport in ('postgres-direct','supabase-management','vercel','app-surface','supabase-edge-logs'));

create function public.record_edge_traffic_snapshot(
  p_user uuid, p_job uuid, p_token uuid, p_project_ref text, p_read boolean
) returns void language plpgsql security definer set search_path = pg_catalog, public as $$
declare job public.execution_jobs;
begin
  if p_project_ref is null or length(p_project_ref) not between 1 and 256 or p_read is null then
    raise exception 'invalid edge traffic snapshot';
  end if;
  select * into job from public.execution_jobs where id=p_job;
  if not found or job.user_id<>p_user or job.kind<>'monitor' or job.status<>'running'
    or job.lease_token is distinct from p_token or job.lease_until<=now() then
    raise exception 'monitor lease unavailable';
  end if;
  insert into public.provider_snapshots(user_id, job_id, transport, scope, completeness, reason)
    values (p_user, p_job, 'supabase-edge-logs', p_project_ref,
      case when p_read then 'complete' else 'failed' end,
      case when p_read then null else 'log_unread' end);
end $$;

revoke all on function public.record_edge_traffic_snapshot(uuid,uuid,uuid,text,boolean) from public, anon, authenticated;
grant execute on function public.record_edge_traffic_snapshot(uuid,uuid,uuid,text,boolean) to service_role;

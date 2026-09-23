-- Bounded retention for customer-intelligence tasks (Step 10B-1d). Accepted
-- results can contain proposed code for a customer's files, so they are kept
-- 30 days after completion, long enough to review or act on, then deleted.
-- Pending tasks that expired, and cancelled tasks, are deleted after a one-day
-- grace so a host polling late still sees a clear state first. Run daily by
-- the scheduled monitor route; service-only.

create function public.purge_intelligence_tasks()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare purged integer;
begin
  delete from public.intelligence_tasks
    where (completed_at is not null and completed_at < now() - interval '30 days')
       or (status = 'pending' and expires_at < now() - interval '1 day')
       or (status = 'cancelled' and created_at < now() - interval '1 day');
  get diagnostics purged = row_count;
  return purged;
end $$;

revoke all on function public.purge_intelligence_tasks() from public, anon, authenticated;
grant execute on function public.purge_intelligence_tasks() to service_role;

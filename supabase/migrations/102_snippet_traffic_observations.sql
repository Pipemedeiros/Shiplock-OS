-- X2 (2026-10-12): traffic the customer-side snippet flags is recorded per
-- repository as observations with source 'snippet', so the hot routes, the
-- rate-limit offer and its check in request_repair_action (093) see the
-- snippet, not only gateway logs. Same bounds, same repository check, same
-- service-only access as 086.
alter table public.traffic_route_observations drop constraint traffic_route_observations_source_check;
alter table public.traffic_route_observations add constraint traffic_route_observations_source_check
  check (source in ('supabase', 'snippet'));

create or replace function public.replace_traffic_observations(p_user uuid, p_repository uuid, p_source text, p_paths jsonb)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted integer;
begin
  if p_source is null or p_source not in ('supabase', 'snippet') or p_paths is null or jsonb_typeof(p_paths) <> 'array'
    or jsonb_array_length(p_paths) > 20
    or exists(select 1 from jsonb_to_recordset(p_paths) as x(path text, "suspiciousRequests" integer)
      where x.path is null or length(x.path) not between 1 and 512 or x."suspiciousRequests" is null or x."suspiciousRequests" <= 0) then
    raise exception 'invalid traffic observations';
  end if;
  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  delete from public.traffic_route_observations where user_id = p_user and repository_id = p_repository and source = p_source;
  insert into public.traffic_route_observations(user_id, repository_id, source, path, suspicious_requests)
    select p_user, p_repository, p_source, x.path, x."suspiciousRequests"
    from jsonb_to_recordset(p_paths) as x(path text, "suspiciousRequests" integer);
  get diagnostics inserted = row_count;
  return inserted;
end $$;

revoke all on function public.replace_traffic_observations(uuid,uuid,text,jsonb) from public, anon, authenticated;
grant execute on function public.replace_traffic_observations(uuid,uuid,text,jsonb) to service_role;

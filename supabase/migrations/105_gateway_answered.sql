-- How the gateway answered flagged sources (2026-10-17). The Supabase API
-- gateway log already carries each response's status code; ShipLock read it
-- and dropped it. Each observed path now keeps how many of its suspicious
-- requests were answered with success (2xx), never more than were seen.
-- Null means not counted (snippet observations, older rows). A success from
-- PostgREST can be an empty list, so this is shown as answered, never as data
-- taken. Same bounds, repository check and service-only access as 102.
alter table public.traffic_route_observations
  add column answered integer check (answered >= 0 and answered <= suspicious_requests);

create or replace function public.replace_traffic_observations(p_user uuid, p_repository uuid, p_source text, p_paths jsonb)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted integer;
begin
  if p_source is null or p_source not in ('supabase', 'snippet') or p_paths is null or jsonb_typeof(p_paths) <> 'array'
    or jsonb_array_length(p_paths) > 20
    or exists(select 1 from jsonb_to_recordset(p_paths) as x(path text, "suspiciousRequests" integer, answered integer)
      where x.path is null or length(x.path) not between 1 and 512 or x."suspiciousRequests" is null or x."suspiciousRequests" <= 0
        or (x.answered is not null and (x.answered < 0 or x.answered > x."suspiciousRequests"))) then
    raise exception 'invalid traffic observations';
  end if;
  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  delete from public.traffic_route_observations where user_id = p_user and repository_id = p_repository and source = p_source;
  insert into public.traffic_route_observations(user_id, repository_id, source, path, suspicious_requests, answered)
    select p_user, p_repository, p_source, x.path, x."suspiciousRequests", x.answered
    from jsonb_to_recordset(p_paths) as x(path text, "suspiciousRequests" integer, answered integer);
  get diagnostics inserted = row_count;
  return inserted;
end $$;

revoke all on function public.replace_traffic_observations(uuid,uuid,text,jsonb) from public, anon, authenticated;
grant execute on function public.replace_traffic_observations(uuid,uuid,text,jsonb) to service_role;

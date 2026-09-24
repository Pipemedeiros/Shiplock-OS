-- Provider-log traffic observations (Step 2F-4). A read-only pull of the
-- customer's Supabase API gateway log, through their own Supabase connection,
-- judges each client by the same rules as the snippet and keeps only the paths
-- that judged clients hit, per repository the customer confirmed for that
-- Supabase project. No IP, hashed or raw, and no request content is stored:
-- only path and count. Each run replaces the repository's rows for its source;
-- readers ignore rows older than 48 hours.
create table public.traffic_route_observations (
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  source text not null check (source in ('supabase')),
  path text not null check (length(path) between 1 and 512),
  suspicious_requests integer not null check (suspicious_requests > 0),
  observed_at timestamptz not null default now(),
  primary key (user_id, repository_id, source, path),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade
);
alter table public.traffic_route_observations enable row level security;
revoke all on public.traffic_route_observations from public, anon, authenticated;
grant select, insert, update, delete on public.traffic_route_observations to service_role;

create function public.replace_traffic_observations(p_user uuid, p_repository uuid, p_source text, p_paths jsonb)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted integer;
begin
  if p_source is null or p_source not in ('supabase') or p_paths is null or jsonb_typeof(p_paths) <> 'array'
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

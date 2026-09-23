-- Traffic bound to a repository through an explicit site (Step 2F-2a).
-- Traffic used to be account-scoped (one traffic_ingest_token per account), so
-- it could never corroborate a repository's findings. A traffic site is one
-- public app host that the customer binds to one of their selected
-- repositories; it has its own ingest token (source 'snippet'), or, later, a
-- provider-issued link (source 'vercel', 2F-3). Events carry the site and
-- repository they arrived under. Traffic never transits ShipLock: the snippet
-- mirrors minimized metadata off the request path and fails open.
create table public.traffic_sites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  host text not null check (host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    and host !~ '^[0-9.]+$' and length(host) <= 253),
  source text not null default 'snippet' check (source in ('snippet','vercel')),
  ingest_token uuid not null unique default gen_random_uuid(),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade
);
create unique index traffic_sites_active_host on public.traffic_sites(user_id, host) where revoked_at is null;
alter table public.traffic_sites enable row level security;
revoke all on public.traffic_sites from public, anon, authenticated;
grant select, insert, update, delete on public.traffic_sites to service_role;

alter table public.traffic_events
  add column site_id uuid references public.traffic_sites(id) on delete set null,
  add column repository_id uuid;
create index traffic_events_repository_created_idx
  on public.traffic_events (user_id, repository_id, created_at desc) where repository_id is not null;

create function public.create_traffic_site(p_user uuid, p_repository uuid, p_host text)
returns table(site_id uuid, ingest_token uuid)
language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_host text := lower(btrim(coalesce(p_host, ''))); v_site public.traffic_sites;
begin
  if v_host !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    or v_host ~ '^[0-9.]+$' or length(v_host) > 253 then
    raise exception 'invalid host';
  end if;
  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text || ':' || v_host, 7363));
  select * into v_site from public.traffic_sites where user_id = p_user and host = v_host and revoked_at is null;
  if found then
    if v_site.repository_id <> p_repository then raise exception 'host already bound'; end if;
    site_id := v_site.id; ingest_token := v_site.ingest_token; return next; return;
  end if;
  insert into public.traffic_sites(user_id, repository_id, host) values (p_user, p_repository, v_host)
    returning id, traffic_sites.ingest_token into site_id, ingest_token;
  return next;
end $$;

create function public.revoke_traffic_site(p_user uuid, p_site uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.traffic_sites set revoked_at = now()
    where id = p_site and user_id = p_user and revoked_at is null;
  return found;
end $$;

revoke all on function public.create_traffic_site(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_traffic_site(uuid,uuid,text) to service_role;
revoke all on function public.revoke_traffic_site(uuid,uuid) from public, anon, authenticated;
grant execute on function public.revoke_traffic_site(uuid,uuid) to service_role;

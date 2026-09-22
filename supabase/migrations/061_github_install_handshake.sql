-- One-time, tenant-bound handshake for GitHub App installation callbacks.
-- Installation ids are not secrets; a callback must still prove that this
-- signed-in browser began an install before it can replace tenant scope.
create table public.github_install_requests (
  user_id uuid primary key references auth.users(id) on delete cascade,
  nonce_hash text not null check (nonce_hash ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
alter table public.github_install_requests enable row level security;
revoke all on public.github_install_requests from public,anon,authenticated;
grant select,insert,update,delete on public.github_install_requests to service_role;

create function public.begin_github_install(p_user uuid, p_nonce_hash text)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_nonce_hash is null or p_nonce_hash !~ '^[a-f0-9]{64}$'
    or not exists(select 1 from auth.users where id=p_user) then return false; end if;
  insert into public.github_install_requests(user_id,nonce_hash,expires_at)
    values(p_user,p_nonce_hash,now()+interval '10 minutes')
    on conflict(user_id) do update set nonce_hash=excluded.nonce_hash,
      expires_at=excluded.expires_at,created_at=now();
  return true;
end $$;

create function public.complete_github_install(
  p_user uuid, p_nonce_hash text, p_installation bigint
)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
declare previous_installation bigint;
begin
  if p_installation is null or p_installation<=0 or p_nonce_hash is null then return false; end if;

  perform 1 from public.github_install_requests
    where user_id=p_user and nonce_hash=p_nonce_hash and expires_at>now() for update;
  if not found then return false; end if;

  select github_installation_id into previous_installation from public.user_profiles
    where id=p_user for update;
  if not found then return false; end if;

  update public.user_profiles set github_installation_id=p_installation,
    github_connected_at=now() where id=p_user;
  if previous_installation is distinct from p_installation then
    update public.repositories set selected=false where user_id=p_user and selected=true;
  end if;
  delete from public.github_install_requests where user_id=p_user;
  return true;
end $$;

revoke all on function public.begin_github_install(uuid,text)
  from public,anon,authenticated;
revoke all on function public.complete_github_install(uuid,text,bigint)
  from public,anon,authenticated;
grant execute on function public.begin_github_install(uuid,text) to service_role;
grant execute on function public.complete_github_install(uuid,text,bigint) to service_role;

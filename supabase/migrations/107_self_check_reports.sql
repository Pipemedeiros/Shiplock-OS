-- The self-check, run by the customer's agent (2026-10-17). ShipLock offers
-- one harmless request per finding (lib/proof/selfCheck.ts) for the founder
-- or their agent to send to a local or preview app; ShipLock never sends it.
-- The agent now reports the status it got over MCP. A report is untrusted
-- agent output: "test ran, reported by your agent", never proof, never a
-- status change. The method and path are ShipLock's own, derived from the
-- finding, never the agent's; the host is where it ran, never the founder's
-- production address. One latest report per finding, service only.
create table public.self_check_reports (
  user_id uuid not null references auth.users(id) on delete cascade,
  finding_row_id uuid not null references public.deep_findings(id) on delete cascade,
  method text not null check (method in ('GET','POST','PUT','PATCH','DELETE')),
  path text not null check (length(path) between 1 and 512),
  status integer not null check (status between 100 and 599),
  target_host text not null check (target_host ~ '^[a-z0-9.\-]{1,253}(:[0-9]{1,5})?$'),
  reported_at timestamptz not null default now(),
  primary key (user_id, finding_row_id)
);
alter table public.self_check_reports enable row level security;
revoke all on public.self_check_reports from public, anon, authenticated;
grant select, insert, update, delete on public.self_check_reports to service_role;

-- The finding must be this user's and still open; the newest report wins.
create function public.record_self_check(p_user uuid, p_finding_row uuid, p_method text, p_path text, p_status integer, p_host text)
returns void language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if not exists(select 1 from public.deep_findings where id = p_finding_row and user_id = p_user and archived_at is null) then
    raise exception 'finding unavailable';
  end if;
  insert into public.self_check_reports(user_id, finding_row_id, method, path, status, target_host)
    values (p_user, p_finding_row, p_method, p_path, p_status, p_host)
    on conflict (user_id, finding_row_id) do update
      set method = excluded.method, path = excluded.path, status = excluded.status,
        target_host = excluded.target_host, reported_at = now();
end $$;
revoke all on function public.record_self_check(uuid,uuid,text,text,integer,text) from public, anon, authenticated;
grant execute on function public.record_self_check(uuid,uuid,text,text,integer,text) to service_role;

-- Agent pull requests (Felipe 2026-10-15): the customer may let their own
-- coding agent request ShipLock fix PRs for one repository, after
-- acknowledging the risks in the dashboard. The agent is the customer's, not
-- ShipLock's. Only the customer turns this on (the dashboard, never a token),
-- so text an agent reads cannot grant itself the right (indirect prompt
-- injection, OWASP LLM06 excessive agency). Same queue, same 30 a day cap,
-- same allowlisted lane (risk-fix-pr); the receipt names the grant it used.
-- ShipLock still never merges.
create table public.agent_pr_grants (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  acknowledgement text not null check (acknowledgement in ('agent-prs-v1')),
  granted_at timestamptz not null default now(),
  revoked_at timestamptz,
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check (revoked_at is null or revoked_at >= granted_at)
);
create unique index agent_pr_grants_one_active on public.agent_pr_grants(user_id, repository_id) where revoked_at is null;
alter table public.agent_pr_grants enable row level security;
revoke all on public.agent_pr_grants from public, anon, authenticated;

alter table public.repair_action_receipts add column agent_grant_id uuid references public.agent_pr_grants(id);
alter table public.repair_action_receipts
  add constraint repair_action_receipts_agent_lane check (agent_grant_id is null or action = 'risk-fix-pr');

create function public.grant_agent_prs(p_user uuid, p_repository uuid, p_ack text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_id uuid;
begin
  if p_ack is distinct from 'agent-prs-v1' then raise exception 'acknowledgement required'; end if;
  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  select id into v_id from public.agent_pr_grants
    where user_id = p_user and repository_id = p_repository and revoked_at is null;
  if found then return v_id; end if;
  insert into public.agent_pr_grants(user_id, repository_id, acknowledgement)
    values (p_user, p_repository, p_ack) returning id into v_id;
  return v_id;
end $$;

create function public.revoke_agent_prs(p_user uuid, p_repository uuid)
returns void language sql security definer set search_path = pg_catalog, public as $$
  update public.agent_pr_grants set revoked_at = now()
    where user_id = p_user and repository_id = p_repository and revoked_at is null;
$$;

-- The agent's request: refused without an active grant, then exactly the
-- customer's queue (request_repair_action keeps the cap, the selection check
-- and idempotency). A receipt created in this transaction records the grant;
-- one a click already made in the same minute stays the click's.
create function public.request_agent_repair_action(p_user uuid, p_repository uuid, p_finding text, p_key text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_grant uuid; v_receipt uuid;
begin
  select id into v_grant from public.agent_pr_grants
    where user_id = p_user and repository_id = p_repository and revoked_at is null for update;
  if not found then raise exception 'agent pull requests off'; end if;
  v_receipt := public.request_repair_action(p_user, p_repository, 'risk-fix-pr', p_finding, null, p_key);
  update public.repair_action_receipts set agent_grant_id = v_grant
    where id = v_receipt and agent_grant_id is null and requested_at = now();
  return v_receipt;
end $$;

revoke all on function public.grant_agent_prs(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.revoke_agent_prs(uuid,uuid) from public, anon, authenticated;
revoke all on function public.request_agent_repair_action(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.grant_agent_prs(uuid,uuid,text) to service_role;
grant execute on function public.revoke_agent_prs(uuid,uuid) to service_role;
grant execute on function public.request_agent_repair_action(uuid,uuid,text,text) to service_role;

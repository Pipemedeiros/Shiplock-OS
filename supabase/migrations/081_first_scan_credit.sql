-- One ShipLock-funded model run per account (Step 3G-1). AGENTS.md: after
-- sign-in, GitHub installation and repository selection, ShipLock funds ONE
-- bounded first scan per account; retries of that run reuse it; repository
-- changes, later runs and account recreation never mint another. Later audits
-- still run every deterministic check, and their AI step reads "not checked"
-- until the customer's own intelligence does that work.
--
-- A credit is claimed only by the audit job holding that run's live lease. It
-- binds the run and the GitHub installation it ran under, so a new account on
-- an installation that already used a credit gets none. It is a ledger with no
-- foreign keys on purpose: deleting the account or the run must not erase it,
-- or deleting and re-creating an account would mint a second funded run. It
-- holds only opaque ids.
create table public.first_scan_credits (
  user_id uuid primary key,
  run_id uuid not null unique,
  github_installation_id bigint not null,
  consumed_at timestamptz not null default now()
);
create index first_scan_credits_installation on public.first_scan_credits(github_installation_id);
alter table public.first_scan_credits enable row level security;
revoke all on public.first_scan_credits from public, anon, authenticated;
grant select, insert, update, delete on public.first_scan_credits to service_role;

create function public.claim_first_scan_credit(p_user uuid, p_run uuid, p_job uuid, p_token uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_credit public.first_scan_credits; v_installation bigint;
begin
  -- Only the worker holding this run's live audit lease may spend.
  if not exists(select 1 from public.execution_jobs where id = p_job and user_id = p_user
      and audit_run_id = p_run and kind = 'audit' and status = 'running'
      and lease_token = p_token and lease_until > now()) then
    return false;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text, 7361));
  select * into v_credit from public.first_scan_credits where user_id = p_user;
  if found then return v_credit.run_id = p_run; end if;
  select github_installation_id into v_installation from public.user_profiles where id = p_user;
  if v_installation is null then return false; end if;
  -- Account recreation on the same installation does not earn a second run.
  perform pg_advisory_xact_lock(v_installation);
  if exists(select 1 from public.first_scan_credits where github_installation_id = v_installation) then
    return false;
  end if;
  insert into public.first_scan_credits(user_id, run_id, github_installation_id)
    values (p_user, p_run, v_installation);
  return true;
end $$;

revoke all on function public.claim_first_scan_credit(uuid,uuid,uuid,uuid) from public, anon, authenticated;
grant execute on function public.claim_first_scan_credit(uuid,uuid,uuid,uuid) to service_role;

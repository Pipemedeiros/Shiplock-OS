-- Per-test proof authorizations (Q5 / Step 6A-1).
-- AGENTS.md: attack-based verification runs only against a disposable replica
-- or an environment the customer explicitly authorized for that exact test.
-- A standing opt-in is not enough. Each authorization names one finding and
-- one table in one selected repository, targets ShipLock's embedded replica
-- only (Felipe 2026-09-23: no paid hosted proving project), carries a
-- statement budget, expires after one hour, and is consumed exactly once by
-- the proof job that runs it (Q6). No run or UI exists yet.
create table public.proof_authorizations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  finding_id text not null check (length(finding_id) between 1 and 1000),
  target_kind text not null default 'replica' check (target_kind in ('replica')),
  table_name text not null check (table_name ~ '^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$'),
  statement_budget integer not null default 60 check (statement_budget between 1 and 200),
  status text not null default 'issued' check (status in ('issued','consumed','revoked')),
  idempotency_key text not null check (length(idempotency_key) between 1 and 200),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '1 hour',
  consumed_at timestamptz,
  unique (user_id, idempotency_key),
  foreign key (repository_id, user_id) references public.repositories(id, user_id) on delete cascade,
  check (expires_at = created_at + interval '1 hour'),
  check ((status = 'consumed') = (consumed_at is not null))
);
create index proof_authorizations_outstanding on public.proof_authorizations (user_id, expires_at) where status = 'issued';
alter table public.proof_authorizations enable row level security;
revoke all on public.proof_authorizations from public, anon, authenticated;
grant select, insert, update, delete on public.proof_authorizations to service_role;

create function public.authorize_proof(p_user uuid, p_repository uuid, p_finding text, p_table text, p_key text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare existing public.proof_authorizations; v_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user::text, 9061));
  select * into existing from public.proof_authorizations where user_id = p_user and idempotency_key = p_key;
  if found then
    if existing.repository_id <> p_repository or existing.finding_id <> p_finding or existing.table_name <> p_table then
      raise exception 'idempotency key reused';
    end if;
    return existing.id;
  end if;
  if not exists(select 1 from public.repositories where id = p_repository and user_id = p_user and selected = true) then
    raise exception 'repository unavailable';
  end if;
  if (select count(*) from public.proof_authorizations
      where user_id = p_user and status = 'issued' and expires_at > now()) >= 5 then
    raise exception 'too many outstanding proofs';
  end if;
  insert into public.proof_authorizations(user_id, repository_id, finding_id, table_name, idempotency_key, created_at, expires_at)
    values (p_user, p_repository, p_finding, p_table, p_key, now(), now() + interval '1 hour')
    returning id into v_id;
  return v_id;
end $$;

create function public.consume_proof_authorization(p_user uuid, p_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.proof_authorizations set status = 'consumed', consumed_at = now()
    where id = p_id and user_id = p_user and status = 'issued' and expires_at > now();
  if not found then raise exception 'proof authorization unavailable'; end if;
  return true;
end $$;

create function public.revoke_proof_authorization(p_user uuid, p_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.proof_authorizations set status = 'revoked'
    where id = p_id and user_id = p_user and status = 'issued';
  return found;
end $$;

revoke all on function public.authorize_proof(uuid,uuid,text,text,text) from public, anon, authenticated;
grant execute on function public.authorize_proof(uuid,uuid,text,text,text) to service_role;
revoke all on function public.consume_proof_authorization(uuid,uuid) from public, anon, authenticated;
grant execute on function public.consume_proof_authorization(uuid,uuid) to service_role;
revoke all on function public.revoke_proof_authorization(uuid,uuid) from public, anon, authenticated;
grant execute on function public.revoke_proof_authorization(uuid,uuid) to service_role;

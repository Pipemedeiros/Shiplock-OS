-- 101: a user's own token reads no table (two-step sign-in at the database).
--
-- ShipLock reads and writes every public table through the service role on
-- the server, after its own gates (lib/dashboard.ts, requireProUser, bearer
-- routes) have checked the session, including aal2 for a user with a verified
-- authenticator (lib/mfa.ts). PostgREST is the one path around those gates:
-- an aal1 token of a user with an authenticator could still read the rows
-- the legacy select-own policies allow (deep_findings, scan_history, and
-- user_profiles.id and is_paid). Supabase's default privileges had also left
-- anon and authenticated select, trigger and maintain on most tables and
-- usage on sequences. No product code depends on any of it.
--
-- So every right those roles hold in public goes, the select-own policies go
-- with them (RLS stays enabled on every table, with no policy, which denies),
-- and postgres's default privileges stop granting them on new tables,
-- sequences and functions. A future table a client must read needs its own
-- explicit grant and an aal-aware policy.
--
-- Not changed: supabase_admin's default privileges (postgres cannot alter
-- them; see 095). ShipLock's migrations run as postgres.

revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

do $$
begin
  if to_regclass('public.deep_findings') is not null then
    drop policy if exists deep_findings_select_own on public.deep_findings;
  end if;
  if to_regclass('public.scan_history') is not null then
    drop policy if exists "users can read own scan history" on public.scan_history;
  end if;
  if to_regclass('public.user_profiles') is not null then
    drop policy if exists "users can read own profile" on public.user_profiles;
  end if;
end $$;

alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated;
-- PUBLIC's execute on a new function is a global default, which a per-schema
-- rule cannot remove; every ShipLock function already revokes it by hand.
alter default privileges for role postgres revoke execute on functions from public;

-- 041 — revoke browser-reachable WRITE grants across every public table
--
-- FOUND 2026-07-30 by the A5 grant check (lib/deep/grantScan.ts) running against
-- our own production database — the check written specifically because we shipped
-- this bug once already in migration 035.
--
-- Migration 035 fixed exactly one table, user_profiles. Every other table still
-- carried Supabase's default broad grants, and `api_tokens` — created after 035,
-- holding token_hash — has the identical problem: `anon` and `authenticated` hold
-- INSERT/UPDATE/DELETE across 14 columns and SELECT on the credential column.
--
-- That is the mechanism the check's copy describes: a table-level grant is
-- inherited by every column added afterwards, and a NEW TABLE starts with the
-- default grants, so the exposure re-widens every time the schema grows. Fixing
-- one table was never going to hold.
--
-- NOT exploitable today, same as 035: RLS is enabled on all of these and only
-- three SELECT policies exist, so writes are denied regardless of the grant. This
-- removes the dependency rather than patching a breach — two independent things
-- should not both have to stay correct for the data to stay safe.
--
-- SAFE TO APPLY: verified that no client component writes to Supabase. The
-- browser client (lib/supabaseBrowser.ts) is used only for auth — sign-in,
-- sign-out, session refresh. Every table write in this codebase goes through a
-- server route using the service-role client, which is unaffected by these
-- grants.

do $$
declare t record;
begin
  for t in
    select tablename from pg_tables where schemaname = 'public'
  loop
    execute format(
      'revoke insert, update, delete, truncate, references on public.%I from anon, authenticated',
      t.tablename
    );
  end loop;
end $$;

-- api_tokens holds token_hash and is only ever read by a server route using the
-- service-role client. The browser has no reason to reach it at all.
revoke select on public.api_tokens from anon, authenticated;

-- The durable half: new tables in this schema start closed rather than
-- inheriting write grants. Without this, the next migration re-opens what this
-- one just closed, which is exactly how 035 came undone.
alter default privileges in schema public
  revoke insert, update, delete, truncate, references on tables from anon, authenticated;

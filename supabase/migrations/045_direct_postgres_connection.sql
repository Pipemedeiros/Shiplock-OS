-- 045 — direct Postgres connection, so the database half is not Supabase-only.
--
-- Everything that makes our database layer worth having depends on Row Level
-- Security, which is standard Postgres, not on Supabase. Restricting ourselves
-- to one host was a transport accident. This column lets a customer on Neon,
-- Railway, Render, RDS, Fly or their own hardware fill the same "your database"
-- slot the Supabase OAuth fills.
--
-- This is NOT a third connection. The historical onboarding friction budget stayed two.
--
-- The credential is stored AES-256-GCM-encrypted by lib/crypto.ts, the same way
-- monitoring anon keys are, and is never written to logs. It is deliberately a
-- separate column from the Supabase token rather than a shared "database
-- credential" column: they are different secrets with different revocation
-- stories, and one column holding either would make "which connection does this
-- customer have?" a parse rather than a lookup.

alter table public.user_profiles
  add column if not exists postgres_dsn_encrypted text,
  -- Host and database only, for display. NEVER the user or password: the
  -- dashboard has to be able to say "connected to db.example.com/app" without
  -- the decrypted secret going anywhere near a page render.
  add column if not exists postgres_display text,
  add column if not exists postgres_connected_at timestamptz,
  add column if not exists postgres_last_scan_at timestamptz;

comment on column public.user_profiles.postgres_dsn_encrypted is
  'AES-256-GCM encrypted read-only Postgres connection string. Service-role only; never returned to a browser.';
comment on column public.user_profiles.postgres_display is
  'host/database only, safe to render. Never contains credentials.';

-- user_profiles already denies all column access to anon/authenticated
-- (migration 041 locked public grants). These columns inherit that, but the
-- historical paywall/grant regression happened on exactly this table
-- before, so assert it rather than assume it.
revoke all (postgres_dsn_encrypted, postgres_display, postgres_connected_at, postgres_last_scan_at)
  on public.user_profiles from anon, authenticated;

do $$
declare
  leaked text;
begin
  select string_agg(grantee || ':' || column_name, ', ')
    into leaked
    from information_schema.column_privileges
   where table_schema = 'public'
     and table_name = 'user_profiles'
     and column_name in ('postgres_dsn_encrypted', 'postgres_display',
                         'postgres_connected_at', 'postgres_last_scan_at')
     and grantee in ('anon', 'authenticated');

  if leaked is not null then
    raise exception 'Direct-Postgres columns are reachable by a public role: %', leaked;
  end if;
end $$;

-- 035 — lock down user_profiles column grants
--
-- FOUND 2026-07-27 while verifying migrations 033/034 against the live database
-- (exactly the check CLAUDE.md tells you to run: query
-- information_schema.column_privileges after applying, not just "the migration
-- succeeded").
--
-- `anon` and `authenticated` held SELECT + INSERT + UPDATE + REFERENCES on
-- EVERY column of user_profiles, including is_paid, paid_until,
-- monitored_anon_key_encrypted, vercel_access_token_encrypted,
-- traffic_ingest_token, verified_report_token, and (newly, via 034) the
-- Supabase Management API tokens. New columns silently inherit whatever
-- table-level grant exists, so every migration that added a column widened the
-- exposure again.
--
-- NOT exploitable as it stands: RLS is enabled on user_profiles and the only
-- policy is "users can read own profile" (SELECT). With no UPDATE or INSERT
-- policy, RLS denies those by default regardless of the grant.
--
-- But it is one policy away from critical. The moment anyone adds the
-- perfectly reasonable-sounding "users can update own profile" policy, every
-- column becomes user-writable — including is_paid and paid_until, which is an
-- instant self-serve paywall bypass, and monitored_project_url, which would let
-- a user point our scanner at infrastructure they don't own. Grants and
-- policies should not have to be correct *together* for this to be safe.
--
-- Least privilege instead. Verified against every call site: the only
-- user-scoped (non-service-role) read of this table is `is_paid`
-- (lib/dashboard.ts, app/(d)/onboarding/page.tsx). Everything else — the
-- webhook, monitoring, deep scans, verified report, traffic, portal — uses the
-- service-role client, which bypasses grants and RLS entirely.

-- anon has no business touching this table at all.
revoke all on public.user_profiles from anon;

-- authenticated: no writes, ever. All writes are service-role.
revoke insert, update, delete, references on public.user_profiles from authenticated;

-- Then narrow SELECT to the two columns actually read with the user's own JWT.
revoke select on public.user_profiles from authenticated;
grant select (id, is_paid) on public.user_profiles to authenticated;

-- The "users can read own profile" RLS policy still applies on top, so a
-- caller sees only their own row, and only those two columns.

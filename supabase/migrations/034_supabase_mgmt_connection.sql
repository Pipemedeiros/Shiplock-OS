-- 034 — Supabase Management API connection (read-only)
--
-- Unblocks the RLS POLICY detector (lib/deep/policyScan.ts), which is built and
-- tested but has never had a way to see a customer's actual policies. An
-- external anon-key scan can only infer that RLS is absent; it cannot read a
-- policy that exists and is wrong. `USING (true)` on the `authenticated` role
-- is the single most common real Supabase critical in AI-built apps, and today
-- we pass it as safe.
--
-- Scope boundary, non-negotiable (AGENTS.md): this connection is READ-ONLY.
-- ShipLock never writes a customer's production database. The Management API's
-- query endpoint can execute arbitrary SQL, so lib/deep/supabaseMgmt.ts guards
-- every statement and refuses anything that isn't a read. DB/RLS fixes stay
-- migration-PR only, exactly as before.

alter table public.user_profiles
  add column if not exists supabase_mgmt_token_encrypted    text,
  add column if not exists supabase_mgmt_refresh_encrypted  text,
  add column if not exists supabase_mgmt_expires_at         timestamptz,
  add column if not exists supabase_mgmt_project_ref        text,
  add column if not exists supabase_mgmt_connected_at       timestamptz;

comment on column public.user_profiles.supabase_mgmt_token_encrypted is
  'AES-256-GCM (lib/crypto.ts) Supabase Management API access token. Read-only '
  'use, service-role access only, decrypted in memory at scan time, never logged.';

comment on column public.user_profiles.supabase_mgmt_project_ref is
  'The project ref this connection is scoped to — the same ref parsed from '
  'monitored_project_url, so the connection can never target another project.';

-- No grants for `authenticated`. These are credentials; only the service-role
-- client touches them, consistent with monitored_anon_key_encrypted and the
-- Vercel/GitHub tokens.

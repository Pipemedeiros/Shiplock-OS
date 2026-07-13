-- Phase 2 (2026-07-06): opt-in Vercel env-var audit. Pro-only, additive.
-- Reuses the deep_findings table (source='vercel') and the archive-on-disconnect
-- rule from migration 021 — nothing there is modified. Verified against Vercel
-- docs: integration access is cleanly scopable (Read-only per scope + selected
-- projects), so this is a narrow read-only grant.

-- Vercel integration credential per user. The access token is AES-256-GCM
-- encrypted (lib/crypto.ts), same standard as monitored_anon_key_encrypted.
-- All four columns are purged to null on disconnect.
alter table public.user_profiles
  add column if not exists vercel_access_token_encrypted text,
  add column if not exists vercel_team_id               text,
  add column if not exists vercel_config_id             text,
  add column if not exists vercel_connected_at          timestamptz;

-- Immutable provider connection epochs (Step 2D).
-- Evidence and repository bindings used to key on sha256(ciphertext), so an
-- OAuth refresh or re-encryption looked like a new connection. An epoch is an
-- opaque 64-hex identity that the application rotates only on a true
-- connect/reconnect and clears on disconnect; refreshes leave it unchanged.
-- Existing connections are backfilled with their current fingerprint so every
-- stored binding and snapshot keeps matching across this migration.

alter table public.user_profiles
  add column vercel_connection_epoch text
    check (vercel_connection_epoch ~ '^[a-f0-9]{64}$'),
  add column supabase_mgmt_connection_epoch text
    check (supabase_mgmt_connection_epoch ~ '^[a-f0-9]{64}$'),
  add column postgres_connection_epoch text
    check (postgres_connection_epoch ~ '^[a-f0-9]{64}$'),
  add column supabase_endpoint_connection_epoch text
    check (supabase_endpoint_connection_epoch ~ '^[a-f0-9]{64}$');

-- Same value lib/deep/providerRepositoryMap.ts computed from the ciphertext.
update public.user_profiles set
  vercel_connection_epoch = case when nullif(btrim(vercel_access_token_encrypted), '') is not null
    then encode(sha256(convert_to(vercel_access_token_encrypted, 'UTF8')), 'hex') end,
  supabase_mgmt_connection_epoch = case when nullif(btrim(supabase_mgmt_token_encrypted), '') is not null
    then encode(sha256(convert_to(supabase_mgmt_token_encrypted, 'UTF8')), 'hex') end,
  postgres_connection_epoch = case when nullif(btrim(postgres_dsn_encrypted), '') is not null
    then encode(sha256(convert_to(postgres_dsn_encrypted, 'UTF8')), 'hex') end,
  supabase_endpoint_connection_epoch = case when nullif(btrim(monitored_anon_key_encrypted), '') is not null
    then encode(sha256(convert_to(monitored_anon_key_encrypted, 'UTF8')), 'hex') end;

-- A usable credential always has an epoch and an absent one never does, so a
-- connect path that forgets to mint one, or a disconnect that forgets to clear
-- it, fails loudly instead of silently reusing an old identity.
alter table public.user_profiles
  add constraint user_profiles_vercel_epoch_presence check (
    (nullif(btrim(vercel_access_token_encrypted), '') is null) = (vercel_connection_epoch is null)),
  add constraint user_profiles_supabase_mgmt_epoch_presence check (
    (nullif(btrim(supabase_mgmt_token_encrypted), '') is null) = (supabase_mgmt_connection_epoch is null)),
  add constraint user_profiles_postgres_epoch_presence check (
    (nullif(btrim(postgres_dsn_encrypted), '') is null) = (postgres_connection_epoch is null)),
  add constraint user_profiles_supabase_endpoint_epoch_presence check (
    (nullif(btrim(monitored_anon_key_encrypted), '') is null) = (supabase_endpoint_connection_epoch is null));

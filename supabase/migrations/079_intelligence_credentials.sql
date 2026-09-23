-- Customer model API key for API-key intelligence mode (Step 10B-2e). One key
-- per account, service-only. The key is stored only as ciphertext
-- (lib/crypto.ts), never returned after write, and never placed in a job; the
-- worker decrypts it at call time. `key_hint` (last 4 characters) lets the
-- dashboard show which key is saved. `epoch` rotates on every save, so a result
-- produced under a replaced key can be told apart. Removing the row removes the
-- key; ShipLock never falls back to its own key.
create table public.intelligence_credentials (
  user_id uuid primary key references auth.users(id) on delete cascade,
  provider text not null check (provider = 'anthropic'),
  key_encrypted text not null check (length(key_encrypted) between 16 and 4096),
  key_hint text not null check (key_hint ~ '^[A-Za-z0-9_-]{4}$'),
  epoch text not null check (epoch ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null default now()
);
alter table public.intelligence_credentials enable row level security;
revoke all on public.intelligence_credentials from public, anon, authenticated;
grant select, insert, update, delete on public.intelligence_credentials to service_role;

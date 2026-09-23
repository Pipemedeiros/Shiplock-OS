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

-- One paid call per API-mode task. The worker claims the task before calling
-- the model; a retried job (e.g. after a crash between the call and the
-- submit) finds it claimed and does not spend again. An unanswered claimed
-- task simply expires and reads "not checked", never clean.
alter table public.intelligence_tasks add column api_claimed_at timestamptz;

create function public.claim_api_intelligence_task(p_user uuid, p_task uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.intelligence_tasks set api_claimed_at = now()
    where id = p_task and user_id = p_user and host = 'api' and status = 'pending'
      and expires_at > now() and api_claimed_at is null;
  return found;
end $$;

revoke all on function public.claim_api_intelligence_task(uuid,uuid) from public, anon, authenticated;
grant execute on function public.claim_api_intelligence_task(uuid,uuid) to service_role;

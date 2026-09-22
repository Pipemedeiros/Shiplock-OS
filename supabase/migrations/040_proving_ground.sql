-- 040_proving_ground.sql
-- Opt-in and kill switch for autonomous behaviour (AGENTS.md autonomy doctrine).
--
-- Both default to the safe value. The proving ground stands up a branch on the
-- customer's Supabase account and runs an adversarial probe against it, which is
-- not something to enable on anyone's behalf — and the kill switch is required
-- by the doctrine to be honoured everywhere, so it belongs next to it.

alter table public.user_profiles
  add column if not exists proving_ground_enabled boolean not null default false,
  -- "monitor only, never act". When true, NOTHING autonomous runs for this
  -- customer, regardless of any other setting.
  add column if not exists autonomy_kill_switch boolean not null default false,
  add column if not exists last_proving_run_at timestamptz;

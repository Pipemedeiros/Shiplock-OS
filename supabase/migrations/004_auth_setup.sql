-- ─────────────────────────────────────────────────────────────────────────────
-- 004_auth_setup.sql
-- user_profiles and scan_history for authenticated users.
-- Run in Supabase SQL editor for the ShipLock project.
-- ─────────────────────────────────────────────────────────────────────────────

-- user_profiles ──────────────────────────────────────────────────────────────
create table if not exists public.user_profiles (
  id                  uuid         references auth.users on delete cascade primary key,
  email               text,
  is_paid             boolean      default false,
  stripe_customer_id  text,
  created_at          timestamptz  default now()
);

alter table public.user_profiles enable row level security;

create policy "users can read own profile"
  on public.user_profiles for select
  using (auth.uid() = id);

create policy "users can update own profile"
  on public.user_profiles for update
  using (auth.uid() = id);

-- Auto-create a profile row whenever a new user signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer
as $$
begin
  insert into public.user_profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- scan_history ────────────────────────────────────────────────────────────────
create table if not exists public.scan_history (
  id               uuid         primary key default gen_random_uuid(),
  user_id          uuid         references auth.users on delete cascade,
  project_url      text,
  project_url_hash text,
  grade            text,
  issue_count      int,
  issues           jsonb,
  created_at       timestamptz  default now()
);

alter table public.scan_history enable row level security;

create policy "users can read own scan history"
  on public.scan_history for select
  using (auth.uid() = user_id);

-- NOTE: inserts are done server-side with the service_role key (bypasses RLS).
-- No insert policy needed for the application layer.

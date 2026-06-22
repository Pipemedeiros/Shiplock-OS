-- 005_bonus_scans.sql
-- Server-side bonus scan counter: prevents race conditions from localStorage-only tracking.

alter table public.user_profiles
  add column if not exists bonus_scans int not null default 0;

-- Atomic decrement: returns remaining count, -1 if none available.
-- Must be called with the user's JWT (not service role) so auth.uid() resolves.
create or replace function public.use_bonus_scan()
returns int language plpgsql security definer
as $$
declare
  remaining int;
begin
  update public.user_profiles
  set bonus_scans = bonus_scans - 1
  where id = auth.uid() and bonus_scans > 0
  returning bonus_scans into remaining;

  if not found then
    return -1;
  end if;

  return remaining;
end;
$$;

-- Atomic increment (cap at 3): called when user shares on X.
-- Must be called with the user's JWT so auth.uid() resolves.
create or replace function public.add_bonus_scan()
returns int language plpgsql security definer
as $$
declare
  new_count int;
begin
  update public.user_profiles
  set bonus_scans = least(bonus_scans + 1, 3)
  where id = auth.uid()
  returning bonus_scans into new_count;

  return coalesce(new_count, 0);
end;
$$;

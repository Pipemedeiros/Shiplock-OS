-- 009_promo_codes.sql
-- Promo code table for granting paid access without payment.

create table if not exists promo_codes (
  id         uuid primary key default gen_random_uuid(),
  code       text not null unique,
  max_uses   int  not null default 1,
  uses_count int  not null default 0,
  created_at timestamptz not null default now()
);

-- Seed codes
insert into promo_codes (code, max_uses) values
  ('JORDAN100', 1),
  ('GENZ100',   1),
  ('LAUNCH50',  50)
on conflict (code) do nothing;

-- Only service role can read/write promo_codes (no RLS needed for client-side).
alter table promo_codes enable row level security;
-- No policies = no client access (service role bypasses RLS).

-- Atomic increment function — returns true if code was valid and consumed.
create or replace function use_promo_code(p_code text)
returns boolean
language plpgsql
security definer
as $$
declare
  v_id uuid;
begin
  update promo_codes
  set    uses_count = uses_count + 1
  where  upper(code) = upper(p_code)
    and  uses_count < max_uses
  returning id into v_id;

  return v_id is not null;
end;
$$;

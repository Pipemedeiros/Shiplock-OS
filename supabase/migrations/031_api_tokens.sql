-- 031_api_tokens.sql
-- ShipLock personal access tokens (PATs) for the MCP coding-agent integration.
-- The MCP server (npx @shiplock/mcp, running on the developer's machine)
-- authenticates to ShipLock's API with one of these instead of the short-lived
-- Supabase session JWT. Only the SHA-256 hash is stored — the raw token is shown
-- once at creation and never again. Service-role only (RLS on, no policy); all
-- access goes through the API with the caller's own session.
create table if not exists public.api_tokens (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  token_hash   text not null unique, -- SHA-256 of the raw token
  name         text not null default 'MCP token',
  created_at   timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);

create index if not exists api_tokens_user_idx on public.api_tokens (user_id) where revoked_at is null;

alter table public.api_tokens enable row level security;
-- No policies: service-role only (deny-all for anon/authenticated), same as the
-- other internal tables. Token issuance/listing/revocation goes through
-- /api/tokens with the caller's verified session.

-- Phase 2 (started 2026-07-05): opt-in GitHub deep access (A03 dependency/CVE
-- scanning). Historically Pro-only, additive. Supabase Management API was
-- deferred at this migration's creation. Everything here is new — no existing column/table/policy
-- is modified.

-- Per-user GitHub App installation. installation_id is not itself a secret
-- (the App private key, held only in env, is); null = not connected. Purged to
-- null on disconnect.
alter table public.user_profiles
  add column if not exists github_installation_id bigint,
  add column if not exists github_connected_at    timestamptz;

-- A03 findings, one row per (user, stable finding id). archived_at implements
-- the archive-on-disconnect rule: non-null = hidden from active view but
-- retained as history. Repeat scans insert only finding_ids not already active.
create table if not exists public.deep_findings (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  source       text not null default 'github',
  finding_id   text not null,
  severity     text not null,
  title        text not null,
  consequence  text not null,
  package_name text,
  version      text,
  vuln_id      text,
  cve_id       text,
  detected_at  timestamptz not null default now(),
  archived_at  timestamptz
);

-- Dedup key for ACTIVE findings only: a given finding id can exist once while
-- active, plus any number of archived historical rows.
create unique index if not exists deep_findings_active_uk
  on public.deep_findings (user_id, source, finding_id)
  where archived_at is null;

create index if not exists deep_findings_user_active_idx
  on public.deep_findings (user_id, source) where archived_at is null;

alter table public.deep_findings enable row level security;

-- Users may read their own findings (active + archived history). All writes go
-- through the service role, which bypasses RLS — no insert/update/delete policy
-- is granted to end users by design.
drop policy if exists deep_findings_select_own on public.deep_findings;
create policy deep_findings_select_own on public.deep_findings
  for select using (auth.uid() = user_id);

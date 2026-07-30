-- 039_graph_facts.sql
-- Persisted collector output for the asset graph (PRODUCT-DESIGN.md §5.1).
--
-- The collectors run on different schedules and different triggers: the source
-- collector runs per pull request (that is when routes change), the database
-- collector runs on the 48h pass, traffic is continuous. The reasoner needs all
-- of them at once. Without somewhere to put facts, the graph could only ever see
-- whatever happened to be collected in the current request — which would make
-- correlation depend on timing, and produce findings that appear and vanish
-- depending on which trigger fired last.
--
-- One row per (user, collector). Latest facts win; there is no history here on
-- purpose. History of FINDINGS already lives in deep_findings and
-- monitoring_snapshots; duplicating raw facts would grow without bound and buy
-- nothing, since a stale fact is worse than no fact for this use.

create table if not exists public.graph_facts (
  user_id    uuid not null references auth.users(id) on delete cascade,
  collector  text not null check (collector in ('source', 'db', 'traffic')),
  facts      jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (user_id, collector)
);

create index if not exists graph_facts_user_idx on public.graph_facts (user_id);

alter table public.graph_facts enable row level security;

-- Service-role only, following the lockdown established in migration 035.
--
-- These facts describe the customer's private architecture — every API route,
-- which tables each one touches, and where the gaps are. That is close to a map
-- of how to attack them, so it must never be readable by `anon` or
-- `authenticated`, not even for the owning user: the dashboard surfaces
-- FINDINGS, which are already paywall-filtered, and never the raw graph.
revoke all on public.graph_facts from anon, authenticated;

-- No policies are defined, so with RLS enabled every non-service-role read
-- returns nothing even if a grant is later added by mistake. Deliberate:
-- defence in depth, not redundancy.

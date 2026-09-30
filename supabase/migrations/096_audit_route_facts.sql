-- 096: the audit keeps the route facts it computed, so the dashboard route map
-- (Q27) is drawn from the full audit rather than the 60-file source monitor.
-- Facts only: paths, files, tables, which controls were read; no source code.
-- audit_runs stays service-only (046 revoked all from anon and authenticated).
alter table public.audit_runs add column if not exists route_facts jsonb;
comment on column public.audit_runs.route_facts is
  'Route facts from this audit (path, file, tables, controls read, helpers). No source code. Service role only.';

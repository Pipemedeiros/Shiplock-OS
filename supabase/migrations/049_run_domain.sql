-- What the business IS, as read from the schema during a given run.
--
-- Stored per-run for the same reason the stack is: the customer should see the
-- model the findings were reasoned from, not one recomputed at page load that
-- may no longer match. It is evidence, never a finding — lib/agent/domain.ts
-- derives it from names, and names can lie.

alter table public.audit_runs
  add column if not exists domain jsonb;

comment on column public.audit_runs.domain is
  'DomainModel from lib/agent/domain.ts: what the business is, read from schema and routes. Evidence for reasoning, never a finding on its own.';

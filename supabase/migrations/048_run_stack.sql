-- The stack the audit read out of the repository, stored with the run.
--
-- Without this the dashboard cannot show a customer what we detected without
-- re-downloading and re-parsing their repository, which is both slow and a
-- second chance to disagree with the run that actually produced the findings.
-- Storing it with the run means the stack shown is the stack REASONED OVER,
-- not a fresh guess -- if they differ, the run's copy is the honest one.
--
-- Additive and nullable: a run written before this column exists reads as
-- "we did not record it", which is different from "we found nothing" and must
-- stay that way.

alter table public.audit_runs
  add column if not exists stack jsonb;

comment on column public.audit_runs.stack is
  'StackReport from lib/agent/stack.ts as observed during THIS run: tools, evidence, and whether auth/database were identifiable.';

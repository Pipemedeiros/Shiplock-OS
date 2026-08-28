-- 047 — what the repository agent needs to say about a finding.
--
-- deep_findings already carries id/severity/title/consequence, which is the
-- shape a dependency advisory needs. An attack path needs more, and every
-- column here exists because the product makes a specific promise about it:
--
--   claims      — the evidence ledger. Each entry is {claim, origin, verified}.
--                 migration 043's `correlation` records which collectors AGREED;
--                 this records WHAT each one said. Without it "why we believe
--                 this" is prose, and confidence is an assertion rather than a
--                 function of the evidence.
--   confidence  — proven | corroborated | inferred, DERIVED from claims, never
--                 typed in by hand. Only lib/proving/* may produce `proven`.
--   fix_kind    — pr | one_click | manual. The autonomy tier. A single "apply"
--                 button for all three would overclaim on the ones where the
--                 intent lives in the customer's head.
--   entry/file  — where it starts and where to look. A finding without a
--                 location is an opinion.
--
-- All additive; existing rows keep working with every column null.

alter table public.deep_findings
  add column if not exists repository_id uuid references public.repositories(id) on delete cascade,
  add column if not exists run_id uuid references public.audit_runs(id) on delete set null,
  add column if not exists attack_class text,
  add column if not exists entry text,
  add column if not exists file text,
  add column if not exists confidence text,
  add column if not exists fix_kind text,
  add column if not exists claims jsonb,
  add column if not exists blast_radius text,
  -- The pull request we opened for this finding, once one exists. Nullable
  -- forever for findings whose fix is a judgement call.
  add column if not exists fix_pr_url text,
  add column if not exists fix_pr_number integer;

create index if not exists deep_findings_repo_active_idx
  on public.deep_findings (repository_id) where archived_at is null;

-- 043_finding_correlation.sql
-- Records WHICH layers independently confirmed a finding.
--
-- findAttackPaths already computes this — every path carries `surfaces`, and the
-- reasoner structurally refuses to emit a path spanning fewer than two of them
-- (lib/graph/attackPaths.ts). Until now that was computed and then thrown away
-- at the persistence boundary: deep_findings stored title/severity/consequence
-- and nothing about how the conclusion was reached.
--
-- That was the single most valuable field to drop, because agreement across
-- layers IS the product. "Your RLS policy is permissive" is something a free
-- scanner says. "Your RLS policy is permissive AND the route serving it has no
-- auth check" is a different claim with a different level of confidence, and the
-- customer cannot tell them apart unless we say so.
--
-- Shape: { "surfaces": ["source","db"], "proven": false } — matching
-- IssueCorrelation in lib/types.ts. Nullable rather than defaulted, because
-- "this finding has no correlation data" is honest for every non-graph source
-- (a dependency CVE has one surface by nature and always will), and a default
-- of '{}' would blur that into "correlated with nothing".

alter table public.deep_findings
  add column if not exists correlation jsonb;

comment on column public.deep_findings.correlation is
  'Which collectors independently confirmed this finding, and whether it was proven on a replica rather than inferred. NULL for single-surface sources, which is not a defect.';

-- No grant changes. deep_findings is already service-role only; correlation is
-- read through the same paywall-filtered server paths as the findings it
-- describes, and (unlike graph_facts) it names collectors, not architecture.

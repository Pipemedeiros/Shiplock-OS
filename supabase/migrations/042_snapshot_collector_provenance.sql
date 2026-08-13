-- 042_snapshot_collector_provenance.sql
-- Records WHICH collectors ran in each monitoring pass, and how each fared.
--
-- Why this is worth a column rather than a log line: without it a snapshot
-- cannot distinguish "this layer reported clean" from "this layer never ran",
-- and those mean opposite things. A pass where the app-surface collector timed
-- out currently produces a snapshot indistinguishable from one where it ran and
-- found nothing — so the finding history, read back later, silently overstates
-- how much was actually checked.
--
-- It also underwrites the one asset a competitor cannot regenerate. graph_facts
-- is explicitly current-state only ("latest facts win; there is no history here
-- on purpose", migration 039), and it is fully re-derivable at any moment from
-- the customer's own GitHub and Supabase — a competitor with the same two
-- connections reconstructs it on demand. monitoring_snapshots is the opposite:
-- append-only, and only someone who watched this customer for six months has six
-- months of their history. Recording collector provenance per pass is what makes
-- that history answer real questions later — "was this finding confirmed by code
-- and database together, or only inferred from one side, and since when" — which
-- is exactly the claim the correlation product is sold on.
--
-- Shape: [{ id, layer, status, durationMs }, ...] matching CollectorOutcome in
-- lib/monitoring/registry.ts. Defaults to an empty array so every pre-existing
-- row stays valid and readers can treat "[]" as "provenance not recorded" — which
-- is honest for the 312 snapshots written before this column existed, rather than
-- backfilling a guess about what ran.

alter table public.monitoring_snapshots
  add column if not exists collectors jsonb not null default '[]'::jsonb;

comment on column public.monitoring_snapshots.collectors is
  'Per-pass collector provenance: which collectors ran, and whether each was ok/skipped/failed/timeout. Empty array means provenance predates the column.';

-- No grant changes. monitoring_snapshots is service-role only (no policies, RLS
-- enabled since migration 020), and this column describes our own internal
-- collection behaviour, so it has even less business reaching a browser than the
-- findings alongside it.

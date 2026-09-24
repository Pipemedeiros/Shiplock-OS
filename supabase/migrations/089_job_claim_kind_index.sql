-- Kind-first ready index for job claims (Q4 / Step 12A).
-- claim_execution_job selects the oldest queued job of ONE kind, but the only
-- ready index (056) is ordered by run_after without kind, so a claim for a
-- kind whose jobs sit late in that order scans every other kind's queued rows
-- first. Measured locally (PGlite, 50,000 accounts, ~85,000 queued jobs over
-- 8 kinds, docs/evaluation/QUEUE-SCALE-2026-09-23.json): claim p95 413 ms
-- without this index, 0.37 ms with it; fairness limits unchanged.
create index execution_jobs_ready_kind
  on public.execution_jobs (kind, run_after, created_at, id)
  where status = 'queued';

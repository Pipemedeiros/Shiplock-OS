-- 023_manual_scan_snapshot_trigger.sql
-- /api/scan now enrolls paid users into continuous monitoring and seeds a
-- baseline snapshot from the scan the user just ran — otherwise the first
-- monitoring pass diffs against nothing and re-alerts every finding the
-- user already saw on their dashboard. That seed row needs its own honest
-- trigger_source label; extend the check constraint to allow it.

ALTER TABLE public.monitoring_snapshots
  DROP CONSTRAINT IF EXISTS monitoring_snapshots_trigger_source_check;

ALTER TABLE public.monitoring_snapshots
  ADD CONSTRAINT monitoring_snapshots_trigger_source_check
  CHECK (trigger_source IN ('manual', 'deploy', 'hourly', 'scheduled_48h'));

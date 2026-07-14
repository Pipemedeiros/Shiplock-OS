-- 027_traffic_alert_action.sql
-- Distinguish block vs alert in the traffic alert-dedup log. Two reasons:
--  1) Escalation: a source that first ALERTS (elevated auth) then escalates to
--     a BLOCK should still send the "blocked" email — the old per-source dedup
--     suppressed it. Deduping per (user, source, ACTION) fixes that: blocks
--     dedup against recent blocks, alerts against recent alerts.
--  2) Dashboard labeling: the "flagged, not blocked" panel should show only
--     true alerts, not block reasons that also get logged here.
ALTER TABLE public.traffic_alert_log
  ADD COLUMN IF NOT EXISTS action text NOT NULL DEFAULT 'alert';

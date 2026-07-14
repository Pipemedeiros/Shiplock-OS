-- 026_session_traffic.sql
-- Session-hijack detection for the edge traffic layer. A stolen session is a
-- VALID token — nothing in config is wrong — so the only signal is behavioural:
-- one session presented from many distinct sources at once. The snippet now
-- sends a salted hash of the session (never the raw token); we store it here
-- and the detector alerts (never auto-blocks — blocking a session risks locking
-- out the real user) when one session_id spans several source_ids.
ALTER TABLE public.traffic_events
  ADD COLUMN IF NOT EXISTS session_id text;

-- Per-session distinct-source lookups within the detection window.
CREATE INDEX IF NOT EXISTS traffic_events_user_session_created_idx
  ON public.traffic_events (user_id, session_id, created_at DESC)
  WHERE session_id IS NOT NULL;

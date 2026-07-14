-- 025_traffic_protection.sql
-- Backs the fail-open edge traffic layer: the customer installs a small
-- middleware snippet that (a) mirrors request metadata here fire-and-forget
-- and (b) enforces a per-site blocklist we publish. Detection runs inline in
-- the ingest route (windowed counts, fail-open, same doctrine as
-- lib/rateLimit.ts) and only hard-blocks high-confidence malicious traffic;
-- softer anomalies alert only. Every block is TTL'd (expires_at) and auto-lifts.
--
-- Same access model as the monitoring tables (migration 020): RLS enabled,
-- ZERO policies => service-role only. Nothing here is ever read with the
-- caller's anon JWT.

-- Per-site ingest/blocklist credential. Unguessable UUID in the snippet, the
-- entire auth boundary for the public ingest + blocklist endpoints (same
-- rationale as monitor_webhook_token: a raw user_id would be enumerable).
ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS traffic_ingest_token uuid DEFAULT gen_random_uuid();

-- Backfill existing rows (DEFAULT only applies to new inserts).
UPDATE public.user_profiles SET traffic_ingest_token = gen_random_uuid()
  WHERE traffic_ingest_token IS NULL;

ALTER TABLE public.user_profiles
  ALTER COLUMN traffic_ingest_token SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_traffic_ingest_token_idx
  ON public.user_profiles (traffic_ingest_token);

-- Mirrored request metadata. High-churn, bounded because the snippet only
-- mirrors auth/api paths. source_id is SHA-256(ip + daily salt) computed at
-- the edge — never a raw IP, so nothing here is PII at rest. No request
-- bodies, no query strings.
CREATE TABLE IF NOT EXISTS public.traffic_events (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES auth.users ON DELETE CASCADE,
  source_id  text        NOT NULL,
  path       text        NOT NULL,
  method     text        NOT NULL,
  ua         text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.traffic_events ENABLE ROW LEVEL SECURITY;
-- No policies — service role only.
-- Windowed per-source counts (the detector's hot query).
CREATE INDEX IF NOT EXISTS traffic_events_user_source_created_idx
  ON public.traffic_events (user_id, source_id, created_at DESC);
-- Recent-activity reads + future retention pruning.
CREATE INDEX IF NOT EXISTS traffic_events_user_created_idx
  ON public.traffic_events (user_id, created_at DESC);

-- Active attacker blocklist. One row per (user, source); upserted on repeat
-- detections to extend the block. expires_at drives auto-lift — the serving
-- route only returns rows with expires_at > now().
CREATE TABLE IF NOT EXISTS public.traffic_blocklist (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES auth.users ON DELETE CASCADE,
  source_id  text        NOT NULL,
  reason     text        NOT NULL,
  severity   text        NOT NULL,
  blocked_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
ALTER TABLE public.traffic_blocklist ENABLE ROW LEVEL SECURITY;
-- No policies — service role only.
CREATE UNIQUE INDEX IF NOT EXISTS traffic_blocklist_user_source_idx
  ON public.traffic_blocklist (user_id, source_id);
CREATE INDEX IF NOT EXISTS traffic_blocklist_user_expires_idx
  ON public.traffic_blocklist (user_id, expires_at);

-- Alert dedup log — same shape/purpose as monitoring_alert_log. Prevents
-- re-alerting the same source within the dedup window if it flaps.
CREATE TABLE IF NOT EXISTS public.traffic_alert_log (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES auth.users ON DELETE CASCADE,
  source_id  text        NOT NULL,
  reason     text        NOT NULL,
  alerted_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.traffic_alert_log ENABLE ROW LEVEL SECURITY;
-- No policies — service role only.
CREATE INDEX IF NOT EXISTS traffic_alert_log_user_source_idx
  ON public.traffic_alert_log (user_id, source_id, alerted_at DESC);

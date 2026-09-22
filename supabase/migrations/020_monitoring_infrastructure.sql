-- 020_monitoring_infrastructure.sql
-- Backs items 1-3 of the monitoring stack (deploy-triggered re-scan, hourly
-- fast pass, 48h deep scan): snapshot storage for the diff engine, an
-- alert-dedup log (7-day window per finding, per AGENTS.md), and a
-- per-user webhook token so the deploy-triggered route can identify which
-- ShipLock account a Vercel/GitHub deploy webhook belongs to without
-- exposing anything guessable (a raw user_id in a public webhook URL is
-- an enumeration risk; a random token is not).

CREATE TABLE IF NOT EXISTS public.monitoring_snapshots (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL REFERENCES auth.users ON DELETE CASCADE,
  trigger_source text        NOT NULL CHECK (trigger_source IN ('deploy', 'hourly', 'scheduled_48h')),
  grade          text,
  findings       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.monitoring_snapshots ENABLE ROW LEVEL SECURITY;
-- No policies — service role only, same pattern as checkout_attempts/promo_codes.
CREATE INDEX IF NOT EXISTS monitoring_snapshots_user_created_idx
  ON public.monitoring_snapshots (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.monitoring_alert_log (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES auth.users ON DELETE CASCADE,
  finding_id text        NOT NULL,
  alerted_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.monitoring_alert_log ENABLE ROW LEVEL SECURITY;
-- No policies — service role only.
CREATE INDEX IF NOT EXISTS monitoring_alert_log_user_finding_idx
  ON public.monitoring_alert_log (user_id, finding_id, alerted_at DESC);

ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS monitor_webhook_token uuid DEFAULT gen_random_uuid();

-- Every existing row needs a token too (DEFAULT only applies to new rows).
UPDATE public.user_profiles SET monitor_webhook_token = gen_random_uuid()
  WHERE monitor_webhook_token IS NULL;

ALTER TABLE public.user_profiles
  ALTER COLUMN monitor_webhook_token SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_monitor_webhook_token_idx
  ON public.user_profiles (monitor_webhook_token);

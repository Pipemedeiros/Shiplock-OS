-- 008_monitoring.sql
-- Per-user daily monitoring configuration.
-- Anon key is stored AES-256-GCM encrypted; raw key never persisted.

ALTER TABLE public.user_profiles
  ADD COLUMN IF NOT EXISTS monitoring_enabled         boolean     default false,
  ADD COLUMN IF NOT EXISTS monitored_project_url      text,
  ADD COLUMN IF NOT EXISTS monitored_anon_key_encrypted text,
  ADD COLUMN IF NOT EXISTS last_monitored_at          timestamptz;

-- 007_add_scan_logs_ip_hash.sql
-- Add ip_hash to scan_logs so the rate limiter can count scans per IP
-- using the database instead of in-memory state (survives cold starts).
-- SHA-256 hash of the IP — no raw IP is ever stored.

ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ip_hash text;

CREATE INDEX IF NOT EXISTS scan_logs_ip_hash_created_at_idx
  ON scan_logs (ip_hash, created_at DESC);

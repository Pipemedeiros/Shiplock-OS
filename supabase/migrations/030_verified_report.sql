-- 030_verified_report.sql
-- "ShipLock Verified" — a shareable, honestly-scoped security-posture
-- attestation the customer can hand to their own investors / enterprise buyers.
-- The public report is addressed by an unguessable per-user token (same
-- auth-by-token pattern as monitor_webhook_token, but a SEPARATE column: this
-- is a read-only share link, independently rotatable and disable-able, and
-- must never double as the scan-trigger token).
--
-- Default OFF: posture is private until the owner explicitly enables sharing.
alter table public.user_profiles
  add column if not exists verified_report_token uuid,
  add column if not exists verified_report_enabled boolean not null default false;

-- Unique so a token maps to exactly one profile; partial (only when set) so the
-- many NULLs don't collide.
create unique index if not exists user_profiles_verified_report_token_uk
  on public.user_profiles (verified_report_token)
  where verified_report_token is not null;

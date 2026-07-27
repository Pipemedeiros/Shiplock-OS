-- 033 — prepaid 6- and 12-month terms
--
-- One product, three ways to pay (see lib/plans.ts). Monthly stays a Stripe
-- subscription governed by Stripe's own renewal/cancel events, and leaves
-- paid_until NULL. The 6- and 12-month terms are one-time charges that buy a
-- fixed window, so access needs an explicit end date.
--
-- Deliberately NOT auto-renewing: an auto-renewing consumer subscription with
-- an early-termination fee is the structure FTC negative-option rules and EU
-- consumer law treat as high-risk, and Stripe won't enforce such a fee
-- natively. Prepaid avoids the whole category.

ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS paid_until timestamptz;

COMMENT ON COLUMN user_profiles.paid_until IS
  'End of a PREPAID access window (6/12-month terms). NULL for the monthly '
  'subscription, whose access is governed by Stripe subscription events. '
  'Swept daily by /api/monitor/scheduled, which flips is_paid false once past.';

-- Partial index: the expiry sweep only ever scans still-paid rows that have a
-- deadline, which is a small minority of the table.
CREATE INDEX IF NOT EXISTS idx_user_profiles_paid_until
  ON user_profiles (paid_until)
  WHERE paid_until IS NOT NULL AND is_paid = true;

-- No new grants. paid_until is written by the service-role webhook and read by
-- the service-role sweep only; `authenticated` has no column privilege here,
-- consistent with how is_paid is already handled.

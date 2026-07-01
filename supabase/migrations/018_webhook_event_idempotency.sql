-- 018_webhook_event_idempotency.sql
-- Fixes the Stripe webhook concurrent-duplicate-delivery race identified in
-- the 2026-07-01 follow-up audit. The previous guard in
-- app/api/webhook/route.ts checked `subscribers` for an existing row by
-- stripe_subscription_id (SELECT ... maybeSingle()) before inserting — a
-- check-then-act pattern with no atomicity guarantee, and stripe_subscription_id
-- is nullable so it wasn't even a reliable key. Two concurrent deliveries of
-- the same event could both observe "no existing row" before either commits.
--
-- Fix: gate the entire handler on Stripe's own event.id (always present,
-- guaranteed unique per event — the idempotency key Stripe's own docs
-- recommend) via a single atomic INSERT into a dedicated table protected by
-- a PRIMARY KEY. Postgres's unique index enforcement makes the
-- check-and-insert atomic: under concurrent delivery, exactly one insert
-- succeeds and the other fails with a 23505 unique-violation, deterministically,
-- with no race window. Service-role only, same pattern as checkout_attempts
-- and promo_codes — no client access needed.
CREATE TABLE IF NOT EXISTS public.stripe_webhook_events (
  event_id   text        PRIMARY KEY,
  event_type text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.stripe_webhook_events ENABLE ROW LEVEL SECURITY;
-- No policies — service role only.

CREATE INDEX IF NOT EXISTS stripe_webhook_events_created_at_idx
  ON public.stripe_webhook_events (created_at DESC);

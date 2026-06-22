-- Run this in your Supabase project: Dashboard → SQL Editor → New query

CREATE TABLE IF NOT EXISTS public.subscribers (
  id                     uuid         DEFAULT gen_random_uuid() PRIMARY KEY,
  email                  text         NOT NULL,
  stripe_customer_id     text,
  stripe_subscription_id text,
  supabase_url           text,
  grade                  text,
  created_at             timestamptz  DEFAULT now()
);

-- Protect subscriber data: anon key has zero access.
-- The service_role key used by the webhook bypasses RLS automatically.
ALTER TABLE public.subscribers ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.subscribers IS
  'ShipLock paid subscribers. Written by the Stripe webhook via service_role only.';

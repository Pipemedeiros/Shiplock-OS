-- 011_security_hardening.sql
-- Fixes found during security audit:

-- CRITICAL: "users can update own profile" had no column/value restriction.
-- Any authenticated user could PATCH their own is_paid to true directly via
-- PostgREST using only the anon key + their own JWT, bypassing Stripe entirely.
-- No legitimate self-service profile update feature exists yet (is_paid is
-- webhook-only; monitoring fields aren't user-facing). Drop until a real
-- feature needs scoped self-update, then re-add restricted to safe columns.
DROP POLICY IF EXISTS "users can update own profile" ON public.user_profiles;

-- Restore the SELECT policy from migration 003 that exists in the repo but
-- was missing live (schema drift) — needed for the public activity ticker.
DROP POLICY IF EXISTS "Anyone can read scan logs" ON public.scan_logs;
CREATE POLICY "Anyone can read scan logs"
  ON public.scan_logs FOR SELECT USING (true);

-- Pin search_path on SECURITY DEFINER functions to prevent search_path
-- hijacking (a malicious schema earlier in the path could otherwise shadow
-- objects these functions reference).
ALTER FUNCTION public.add_bonus_scan() SET search_path = public, pg_temp;
ALTER FUNCTION public.use_bonus_scan() SET search_path = public, pg_temp;
ALTER FUNCTION public.use_promo_code(text) SET search_path = public, pg_temp;
ALTER FUNCTION public.handle_new_user() SET search_path = public, pg_temp;

-- handle_new_user is a trigger-only function; it has no business being
-- directly callable via PostgREST RPC.
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;

-- DB-backed rate limiting for /api/checkout (prevents Stripe checkout
-- session spam). Mirrors scan_logs' ip_hash pattern.
CREATE TABLE IF NOT EXISTS public.checkout_attempts (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_hash    text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.checkout_attempts ENABLE ROW LEVEL SECURITY;
-- No policies — service role only, no client access needed.
CREATE INDEX IF NOT EXISTS checkout_attempts_ip_hash_created_at_idx
  ON public.checkout_attempts (ip_hash, created_at DESC);

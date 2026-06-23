-- 014_apply_missing_bonus_scan_rpcs.sql
-- Migration 006 (006_bonus_scan_rpcs.sql) was confirmed never applied to the
-- live database during the 2026-06-23 migration reconciliation audit — only
-- the 0-arg, auth.uid()-based overloads from 005 existed live. This applies
-- 006's intended functions now, bringing live schema in line with the
-- migrations folder, plus the same search_path/grant hardening already
-- applied to every other SECURITY DEFINER function in 011.
--
-- app/api/scan/route.ts does not call these uuid-parameterized overloads
-- (it uses the 0-arg version via the caller's own JWT, per 005's design) —
-- these exist for the documented future use case in 006's own comment:
-- "service-role callers (e.g. webhooks) to grant/consume bonus scans for a
-- specific user without a user JWT."

CREATE OR REPLACE FUNCTION public.add_bonus_scan(user_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE public.user_profiles
  SET bonus_scans = LEAST(bonus_scans + 1, 3)
  WHERE id = user_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_bonus_scan(user_id uuid)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE remaining int;
BEGIN
  UPDATE public.user_profiles
  SET bonus_scans = GREATEST(bonus_scans - 1, 0)
  WHERE id = user_id AND bonus_scans > 0
  RETURNING bonus_scans INTO remaining;
  RETURN COALESCE(remaining, -1);
END;
$$;

-- Unlike the 0-arg overloads (intentionally anon/authenticated-callable,
-- gated by auth.uid()), these take an arbitrary user_id with no ownership
-- check at all — exposing them via PostgREST RPC would let any caller grant
-- or drain ANY other user's bonus scans. Service-role only, per their
-- documented intent.
REVOKE EXECUTE ON FUNCTION public.add_bonus_scan(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.use_bonus_scan(uuid) FROM PUBLIC, anon, authenticated;

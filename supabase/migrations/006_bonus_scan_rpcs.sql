-- 006_bonus_scan_rpcs.sql
-- Overloaded bonus-scan helpers that accept an explicit user_id parameter.
-- These complement the auth.uid()-based functions in 005 and allow
-- service-role callers (e.g. webhooks) to grant/consume bonus scans
-- for a specific user without a user JWT.

CREATE OR REPLACE FUNCTION public.add_bonus_scan(user_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE public.user_profiles
  SET bonus_scans = LEAST(bonus_scans + 1, 3)
  WHERE id = user_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_bonus_scan(user_id uuid)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE remaining int;
BEGIN
  UPDATE public.user_profiles
  SET bonus_scans = GREATEST(bonus_scans - 1, 0)
  WHERE id = user_id AND bonus_scans > 0
  RETURNING bonus_scans INTO remaining;
  RETURN COALESCE(remaining, -1);
END;
$$;

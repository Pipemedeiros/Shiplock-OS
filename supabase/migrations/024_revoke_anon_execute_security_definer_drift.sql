-- 024_revoke_anon_execute_security_definer_drift.sql
-- Supabase's own Security Advisor (privileged, not visible to the external
-- anon-key scan) flagged three SECURITY DEFINER functions still executable
-- by anon/authenticated via /rest/v1/rpc/* — drift the earlier hardening
-- (014 for add_bonus_scan(uuid)/use_bonus_scan(uuid), 017 for
-- use_promo_code(text)) missed, because these are the NO-ARGUMENT overloads:
--
--   add_bonus_scan()   — no-arg overload; (uuid) version already locked in 014
--   use_bonus_scan()   — no-arg overload; (uuid) version already locked in 014
--   rls_auto_enable()  — the ddl_command_end event-trigger function (019);
--                        never meant to be API-callable at all
--
-- Confirmed live via pg_proc: the (uuid) overloads have no anon/authenticated
-- EXECUTE grant (correct), the no-arg overloads still do. No application code
-- calls the no-arg versions (grep across app/lib/components: none — only a
-- doc comment in lib/supabase.ts). Revoking is safe: the (uuid) RPCs the app
-- would use are untouched, and the event trigger fires rls_auto_enable() as
-- the trigger owner regardless of direct EXECUTE grants. Same remediation
-- pattern as 014/017.

REVOKE EXECUTE ON FUNCTION public.add_bonus_scan()  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.use_bonus_scan()  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;

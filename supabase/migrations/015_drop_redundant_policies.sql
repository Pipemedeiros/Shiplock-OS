-- 015_drop_redundant_policies.sql
-- Cleanup of drift found during the 2026-06-23 migration reconciliation audit:
-- 4 extra RLS policies existed live on "subscribers" gated on
-- auth.role() = 'service_role', and 2 extra duplicate anon-scoped policies
-- existed live on "feedback" — none declared in 001_create_subscribers.sql
-- or 002_create_feedback.sql. Functionally redundant (service_role bypasses
-- RLS regardless of policies; "public"-role policies already cover anon),
-- not a security hole, but undocumented drift adding confusion. Removing to
-- match the migrations folder's original, simpler intent.

DROP POLICY IF EXISTS "Only service role can select subscribers" ON public.subscribers;
DROP POLICY IF EXISTS "Only service role can insert subscribers" ON public.subscribers;
DROP POLICY IF EXISTS "Only service role can update subscribers" ON public.subscribers;
DROP POLICY IF EXISTS "Only service role can delete subscribers" ON public.subscribers;

DROP POLICY IF EXISTS "anon can insert feedback" ON public.feedback;
DROP POLICY IF EXISTS "anon can read feedback" ON public.feedback;

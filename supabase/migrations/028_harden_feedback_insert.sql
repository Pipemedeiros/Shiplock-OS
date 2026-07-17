-- 028_harden_feedback_insert.sql
-- Hardening pass (dogfooding our own advisors): the `feedback` table had an
-- unrestricted INSERT policy (`WITH CHECK (true)`) letting anyone with the anon
-- key flood rows — a spam / storage-abuse vector. The public feedback terminal
-- route isn't built, so nothing legitimately inserts via anon. Drop the policy
-- to lock the table to service-role only (RLS on, no policy = deny all for
-- anon/authenticated), matching the other internal tables. Re-add a constrained
-- policy (e.g. rate-limited, with a WITH CHECK) if/when the feature ships.
DROP POLICY IF EXISTS "Anyone can insert feedback" ON public.feedback;

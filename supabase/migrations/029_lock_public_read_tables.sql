-- 029_lock_public_read_tables.sql
-- Dogfooding our new RLS policy-logic detector (lib/deep/policyScan.ts) against
-- our OWN database surfaced two tables with `USING (true)` SELECT policies for
-- role {public} — i.e. world-readable to any anon caller:
--   * feedback  — the public feedback terminal was never built; its INSERT was
--                 already locked in migration 028. The leftover public SELECT is
--                 dead surface that exposes any rows to the anon key.
--   * scan_logs — anonymous scan bookkeeping. Only ever written/read via the
--                 service-role client (app/api/scan/route.ts, getSupabaseAdmin);
--                 the `/api/recent-scans` ticker that might read it publicly was
--                 never built. Public read exposes other users' scan metadata.
-- Neither is read by an anon/authenticated client anywhere in the app (verified),
-- so dropping these policies leaves RLS enabled with no policy = deny-all for
-- anon/authenticated, service-role unaffected — matching every other internal
-- table. Reversible: re-add a scoped SELECT policy if/when either feature ships.
DROP POLICY IF EXISTS "Anyone can read feedback" ON public.feedback;
DROP POLICY IF EXISTS "Anyone can read scan logs" ON public.scan_logs;

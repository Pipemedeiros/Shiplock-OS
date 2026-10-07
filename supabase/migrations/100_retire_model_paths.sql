-- 100: retire the model paths ShipLock no longer has (Felipe, 2026-10-01:
-- ShipLock pays for no intelligence; approved for release 2026-10-06).
--
-- * intelligence_credentials (079) held customer model keys for the removed
--   API-key mode. Nothing has written a key since that mode was removed; a
--   customer could erase a stored key from Settings for a release. Dropping
--   the table erases any that remain. Its claim function goes with it.
-- * first_scan_credits and claim_first_scan_credit (081) funded a ShipLock
--   model call on the first scan; no code path has called them since.
-- * shape_intelligence_task (098) is internal to the security-definer task
--   functions. Supabase's default privileges granted service_role execute on
--   it; nothing calls it directly, so that grant is revoked.
--
-- model_usage_receipts (092) is kept as history until Felipe decides.

drop function if exists public.claim_api_intelligence_task(uuid, uuid);
drop table if exists public.intelligence_credentials;

drop function if exists public.claim_first_scan_credit(uuid, uuid, uuid, uuid);
drop table if exists public.first_scan_credits;

revoke all on function public.shape_intelligence_task(uuid, text, uuid, uuid, jsonb) from public, anon, authenticated, service_role;

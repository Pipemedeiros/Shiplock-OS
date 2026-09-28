-- 094: wake the durable job worker every minute from Supabase (Q19).
--
-- Queued jobs otherwise run only when a request or the daily cron wakes them.
-- pg_cron calls POST /api/jobs/drain once a minute through pg_net; the route
-- claims at most one job per call under its existing lease and fence.
--
-- Two Vault secrets, created out of band and never in this file:
--   shiplock_drain_url    the full drain URL of the production deployment
--   shiplock_cron_secret  the same value as the deployment's CRON_SECRET
-- Until both exist the scheduled statement selects nothing and sends nothing.
--
-- Where pg_cron or pg_net is unavailable (the local PGlite suite) this whole
-- migration is a no-op.
do $migration$
begin
  if not exists (select 1 from pg_available_extensions where name = 'pg_cron')
     or not exists (select 1 from pg_available_extensions where name = 'pg_net') then
    raise notice 'pg_cron or pg_net unavailable: worker wake not scheduled';
    return;
  end if;

  create extension if not exists pg_net with schema extensions;
  create extension if not exists pg_cron;

  -- Client roles gain no new rights from these extensions.
  revoke all on schema net from anon, authenticated;
  revoke execute on all functions in schema net from anon, authenticated;

  perform cron.schedule('shiplock-drain-worker', '* * * * *', $job$
    select net.http_post(
      url => (select decrypted_secret from vault.decrypted_secrets where name = 'shiplock_drain_url'),
      headers => jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'shiplock_cron_secret')
      ),
      body => '{}'::jsonb,
      timeout_milliseconds => 60000
    )
    where exists (select 1 from vault.decrypted_secrets where name = 'shiplock_drain_url')
      and exists (select 1 from vault.decrypted_secrets where name = 'shiplock_cron_secret');
  $job$);
end
$migration$;

-- 095: client roles cannot reach pg_net (fixes 094).
--
-- pg_net grants its functions and schema usage to PUBLIC. 094 revoked from
-- anon and authenticated by name, which does not remove a PUBLIC grant, so on
-- 2026-09-29 both roles could still execute net.http_post. The schema is not
-- exposed through the Data API, but a function that makes outbound requests
-- must not be reachable by a client role at all.
--
-- The worker wake (cron job run as postgres) and service_role keep access
-- through explicit grants. A no-op where the net schema does not exist.
do $migration$
begin
  if not exists (select 1 from pg_namespace where nspname = 'net') then
    raise notice 'no net schema: nothing to revoke';
    return;
  end if;

  revoke all on schema net from public, anon, authenticated;
  revoke execute on all functions in schema net from public, anon, authenticated;

  grant usage on schema net to postgres;
  grant execute on all functions in schema net to postgres;
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant usage on schema net to service_role;
    grant execute on all functions in schema net to service_role;
  end if;
end
$migration$;

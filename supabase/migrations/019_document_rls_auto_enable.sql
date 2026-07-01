-- 019_document_rls_auto_enable.sql
-- Documents the `ensure_rls` event trigger (function public.rls_auto_enable())
-- found live during the 2026-07-01 follow-up audit but absent from the
-- migrations folder — the same kind of untracked drift 011/014/015 already
-- reconciled once. Confirmed intentional by the project owner, added by hand
-- outside the migration workflow at some point. This migration captures
-- current live state exactly — no behavior change — so the migrations
-- folder matches reality going forward.
--
-- What it does: on ddl_command_end, for any CREATE TABLE / CREATE TABLE AS /
-- SELECT INTO landing in the public schema, automatically runs
-- ALTER TABLE ... ENABLE ROW LEVEL SECURITY on it. A defense-in-depth safety
-- net against forgetting to turn on RLS for a newly created table. Owned by
-- `postgres` (not a Supabase-managed extension trigger — those live in the
-- `extensions` schema and are owned by extension roles).

CREATE OR REPLACE FUNCTION public.rls_auto_enable()
 RETURNS event_trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$function$;

-- CREATE EVENT TRIGGER has no IF NOT EXISTS / OR REPLACE form — guard with
-- an existence check so this migration is a true no-op on a database where
-- the trigger is already present (which is the case live right now).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'ensure_rls') THEN
    CREATE EVENT TRIGGER ensure_rls ON ddl_command_end EXECUTE FUNCTION public.rls_auto_enable();
  END IF;
END;
$$;

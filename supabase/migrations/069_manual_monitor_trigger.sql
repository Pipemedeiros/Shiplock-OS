-- Customer-requested rescans (Step 3F-C2c-5). Dashboard "check now" actions
-- used to collect inside the web request and write outside any lease. They now
-- admit the same identity-only monitor job as deploy, recorded honestly as
-- 'manual' (monitoring_snapshots already accepts that label, migration 023).

alter table public.monitoring_job_context
  drop constraint monitoring_job_context_trigger_source_check;
alter table public.monitoring_job_context
  add constraint monitoring_job_context_trigger_source_check
  check (trigger_source in ('manual','deploy','hourly','scheduled_48h'));

create or replace function public.enqueue_monitoring_job(
  p_user uuid,p_trigger text,p_key text
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job_id uuid; existing_trigger text;
begin
  if p_trigger not in ('manual','deploy','hourly','scheduled_48h')
    or p_key is null or length(p_key) not between 1 and 256 then
    raise exception 'invalid monitoring context';
  end if;
  if not exists(select 1 from public.user_profiles p where p.id=p_user and (
      (p_trigger='hourly' and p.monitoring_enabled=true
        and nullif(btrim(p.monitored_project_url),'') is not null
        and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
      or (p_trigger in ('manual','deploy','scheduled_48h') and (
        (p.monitoring_enabled=true and nullif(btrim(p.monitored_project_url),'') is not null
          and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
        or nullif(btrim(p.postgres_dsn_encrypted),'') is not null
        or nullif(btrim(p.vercel_access_token_encrypted),'') is not null
        or (nullif(btrim(p.supabase_mgmt_token_encrypted),'') is not null
          and nullif(btrim(p.supabase_mgmt_project_ref),'') is not null)
        or (p.monitoring_enabled=true and nullif(btrim(p.monitored_app_url),'') is not null)))
    )) then raise exception 'monitoring unavailable'; end if;
  v_job_id:=public.enqueue_execution_job(p_user,null,'monitor',p_key);
  insert into public.monitoring_job_context(job_id,user_id,trigger_source)
    values(v_job_id,p_user,p_trigger) on conflict(job_id) do nothing;
  select trigger_source into existing_trigger from public.monitoring_job_context where monitoring_job_context.job_id=v_job_id;
  if existing_trigger is distinct from p_trigger then raise exception 'idempotency context mismatch'; end if;
  return v_job_id;
end $$;

revoke all on function public.enqueue_monitoring_job(uuid,text,text) from public,anon,authenticated;
grant execute on function public.enqueue_monitoring_job(uuid,text,text) to service_role;

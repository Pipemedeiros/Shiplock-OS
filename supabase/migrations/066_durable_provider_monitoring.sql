-- Monitoring jobs carry only tenant and trigger identity. Workers reread the
-- current encrypted connection fields; credentials and provider payloads never
-- enter queue rows.
alter table public.execution_jobs drop constraint execution_jobs_kind_check;
alter table public.execution_jobs add constraint execution_jobs_kind_check
  check (kind in ('audit','source','monitor','dependency','graph','pr-check','notification'));
alter table public.execution_jobs add constraint execution_jobs_id_user_unique unique(id,user_id);

create table public.monitoring_job_context (
  job_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  trigger_source text not null check (trigger_source in ('deploy','hourly','scheduled_48h')),
  created_at timestamptz not null default now(),
  foreign key(job_id,user_id) references public.execution_jobs(id,user_id) on delete cascade
);
alter table public.monitoring_job_context enable row level security;
revoke all on public.monitoring_job_context from public,anon,authenticated;
grant select,insert,update,delete on public.monitoring_job_context to service_role;

create function public.enqueue_monitoring_job(
  p_user uuid,p_trigger text,p_key text
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job_id uuid; existing_trigger text;
begin
  if p_trigger not in ('deploy','hourly','scheduled_48h')
    or p_key is null or length(p_key) not between 1 and 256 then
    raise exception 'invalid monitoring context';
  end if;
  if not exists(select 1 from public.user_profiles p where p.id=p_user and (
      (p_trigger='hourly' and p.monitoring_enabled=true
        and nullif(btrim(p.monitored_project_url),'') is not null
        and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
      or (p_trigger in ('deploy','scheduled_48h') and (
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

create function public.enqueue_due_monitoring_passes(
  p_trigger text,p_cutoff timestamptz,p_window text,p_limit integer default 100
)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public as $$
declare candidate record; job_id uuid; eligible_count integer:=0; admitted_count integer:=0; failed_count integer:=0;
begin
  if p_trigger not in ('hourly','scheduled_48h') or p_cutoff is null
    or p_window is null or length(p_window) not between 1 and 32
    or p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid monitoring admission';
  end if;
  for candidate in
    select p.id from public.user_profiles p
    where (
      (p_trigger='hourly' and p.monitoring_enabled=true
        and nullif(btrim(p.monitored_project_url),'') is not null
        and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
      or (p_trigger='scheduled_48h' and (
        (p.monitoring_enabled=true and nullif(btrim(p.monitored_project_url),'') is not null
          and nullif(btrim(p.monitored_anon_key_encrypted),'') is not null)
        or nullif(btrim(p.postgres_dsn_encrypted),'') is not null
        or nullif(btrim(p.vercel_access_token_encrypted),'') is not null
        or (nullif(btrim(p.supabase_mgmt_token_encrypted),'') is not null
          and nullif(btrim(p.supabase_mgmt_project_ref),'') is not null)
        or (p.monitoring_enabled=true and nullif(btrim(p.monitored_app_url),'') is not null)))
    ) and case when p_trigger='hourly'
      then p.last_hourly_pass_at is null or p.last_hourly_pass_at<p_cutoff
      else p.last_monitored_at is null or p.last_monitored_at<p_cutoff end
    and not exists(select 1 from public.execution_jobs j where j.user_id=p.id and j.kind='monitor'
      and j.deduplication_key='scheduled-monitor:'||p_trigger||':'||p.id::text||':'||p_window)
    order by case when p_trigger='hourly' then p.last_hourly_pass_at else p.last_monitored_at end asc nulls first,p.id
    limit p_limit
  loop
    eligible_count:=eligible_count+1;
    begin
      job_id:=public.enqueue_monitoring_job(candidate.id,p_trigger,
        'scheduled-monitor:'||p_trigger||':'||candidate.id::text||':'||p_window);
      if job_id is null then failed_count:=failed_count+1; else admitted_count:=admitted_count+1; end if;
    exception when others then failed_count:=failed_count+1;
    end;
  end loop;
  return jsonb_build_object('eligible',eligible_count,'admitted',admitted_count,
    'failed',failed_count,'limited',eligible_count=p_limit);
end $$;

revoke all on function public.enqueue_monitoring_job(uuid,text,text) from public,anon,authenticated;
revoke all on function public.enqueue_due_monitoring_passes(text,timestamptz,text,integer) from public,anon,authenticated;
grant execute on function public.enqueue_monitoring_job(uuid,text,text) to service_role;
grant execute on function public.enqueue_due_monitoring_passes(text,timestamptz,text,integer) to service_role;

create table public.monitoring_notification_batches (
  job_id uuid primary key,
  source_job_id uuid not null unique,
  user_id uuid not null references auth.users(id) on delete cascade,
  findings jsonb not null check (jsonb_typeof(findings)='array' and jsonb_array_length(findings) between 1 and 100),
  created_at timestamptz not null default now(),
  foreign key(job_id,user_id) references public.execution_jobs(id,user_id) on delete cascade,
  foreign key(source_job_id,user_id) references public.execution_jobs(id,user_id) on delete cascade
);
alter table public.monitoring_notification_batches enable row level security;
revoke all on public.monitoring_notification_batches from public,anon,authenticated;
grant select,insert,update,delete on public.monitoring_notification_batches to service_role;

create function public.enqueue_monitoring_notifications(
  p_user uuid,p_source_job uuid,p_token uuid,p_findings jsonb
)
returns uuid language plpgsql security definer set search_path=pg_catalog,public as $$
declare source_job public.execution_jobs; notification_job uuid; existing_job uuid;
begin
  if p_findings is null or jsonb_typeof(p_findings)<>'array'
    or jsonb_array_length(p_findings)>100 or pg_column_size(p_findings)>262144 then
    raise exception 'invalid notification payload';
  end if;
  if jsonb_array_length(p_findings)=0 then return null; end if;
  if exists(select 1 from jsonb_to_recordset(p_findings) as finding(
      id text,severity text,title text,consequence text)
    where finding.id is null or length(finding.id) not between 1 and 1000
      or finding.severity not in ('CRITICAL','WARNING','INFO')
      or finding.title is null or length(finding.title) not between 1 and 1000
      or finding.consequence is null or length(finding.consequence) not between 1 and 20000)
    then raise exception 'invalid notification finding'; end if;
  select * into source_job from public.execution_jobs where id=p_source_job for update;
  if not found or source_job.user_id<>p_user or source_job.kind<>'monitor'
    or source_job.status<>'running' or source_job.lease_token is distinct from p_token
    or source_job.lease_until<=now() then raise exception 'monitor lease unavailable'; end if;
  select job_id into existing_job from public.monitoring_notification_batches where source_job_id=p_source_job;
  if found then return existing_job; end if;
  notification_job:=public.enqueue_execution_job(p_user,null,'notification','notification-after-monitor:'||p_source_job::text);
  insert into public.monitoring_notification_batches(job_id,source_job_id,user_id,findings)
    values(notification_job,p_source_job,p_user,p_findings);
  return notification_job;
end $$;

revoke all on function public.enqueue_monitoring_notifications(uuid,uuid,uuid,jsonb) from public,anon,authenticated;
grant execute on function public.enqueue_monitoring_notifications(uuid,uuid,uuid,jsonb) to service_role;

create function public.stamp_hourly_monitor_attempt(
  p_user uuid,p_job uuid,p_token uuid
)
returns boolean language plpgsql security definer set search_path=pg_catalog,public as $$
begin
  if not exists(select 1 from public.execution_jobs j
    join public.monitoring_job_context c on c.job_id=j.id and c.user_id=j.user_id
    where j.id=p_job and j.user_id=p_user and j.kind='monitor' and j.status='running'
      and j.lease_token=p_token and j.lease_until>now() and c.trigger_source='hourly')
    then return false; end if;
  update public.user_profiles set last_hourly_pass_at=now() where id=p_user;
  return found;
end $$;

revoke all on function public.stamp_hourly_monitor_attempt(uuid,uuid,uuid) from public,anon,authenticated;
grant execute on function public.stamp_hourly_monitor_attempt(uuid,uuid,uuid) to service_role;

-- 037 — traffic pulse aggregate
--
-- Powers the dashboard's "we are watching" panel. The first cut of this read
-- pulled raw traffic_events rows into the serverless function and counted them
-- in JS. That is wrong twice over: at ICP scale a 48h window is tens of
-- thousands of rows (a 1,000-user app mirrors ~600k requests/month), so the
-- read is expensive on every dashboard load AND any LIMIT makes the headline
-- count silently understate reality — which is the one thing this panel must
-- never do, since its whole job is to be a truthful record of work done.
--
-- Aggregate in Postgres. One indexed scan, a handful of rows back.
--
-- SECURITY INVOKER (the default) deliberately — this is called only by the
-- service-role client, which bypasses RLS anyway. No SECURITY DEFINER, and no
-- execute grant to anon/authenticated: see migration 024, which had to clean up
-- exactly that kind of drift.

create or replace function public.traffic_pulse(
  p_user_id uuid,
  p_window_hours int default 48,
  p_buckets int default 24
)
returns table (
  watched bigint,
  sources bigint,
  turned_away bigint,
  bucket_index int,
  bucket_count bigint
)
language sql
stable
as $$
  with win as (
    select now() - make_interval(hours => p_window_hours) as since,
           (p_window_hours * 3600.0) / p_buckets as bucket_seconds
  ),
  ev as (
    select e.source_id,
           e.created_at,
           (b.source_id is not null) as from_blocked
      from public.traffic_events e
      left join public.traffic_blocklist b
        on b.user_id = e.user_id and b.source_id = e.source_id
     where e.user_id = p_user_id
       and e.created_at >= (select since from win)
  ),
  bucketed as (
    select least(
             p_buckets - 1,
             greatest(0, floor(extract(epoch from (created_at - (select since from win)))
                               / (select bucket_seconds from win))::int)
           ) as idx
      from ev
  )
  select
    (select count(*) from ev)                              as watched,
    (select count(distinct source_id) from ev)             as sources,
    (select count(*) from ev where from_blocked)           as turned_away,
    b.idx                                                  as bucket_index,
    count(*)                                               as bucket_count
  from bucketed b
  group by b.idx
  order by b.idx;
$$;

comment on function public.traffic_pulse(uuid, int, int) is
  'Dashboard traffic-pulse aggregate: total requests inspected, distinct sources, '
  'requests from blocked sources, and per-bucket counts over the window. '
  'Service-role only — no execute grant to anon/authenticated.';

revoke all on function public.traffic_pulse(uuid, int, int) from public, anon, authenticated;

create index if not exists idx_traffic_events_user_created
  on public.traffic_events (user_id, created_at desc);

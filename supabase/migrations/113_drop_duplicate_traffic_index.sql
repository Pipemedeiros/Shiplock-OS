-- 113: one index per shape (2026-10-20). 025 created traffic_events_user_created_idx
-- and 037 created idx_traffic_events_user_created on the same columns,
-- (user_id, created_at desc). Every insert maintained both; the Supabase
-- performance advisor reported it as its one warning. 025's copy stays.
drop index if exists public.idx_traffic_events_user_created;

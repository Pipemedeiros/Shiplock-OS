-- Model usage receipts (Q10 / Step 12B, cost evidence).
-- AGENTS.md requires measuring hosted cost per first scan before launch, but
-- model usage was only logged. Each model call now leaves one receipt: who
-- it was for, why, who paid (ShipLock or the customer), the model, and token
-- counts. Never prompt or output text. Run ids carry no foreign key so a
-- receipt outlives run and task retention; cost history must not vanish
-- when results are purged.
create table public.model_usage_receipts (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  purpose text not null check (purpose in ('first_scan','customer_api','narrative','scan_report','proving')),
  funded_by text not null check (funded_by in ('shiplock','customer')),
  model text not null check (length(model) between 1 and 100),
  input_tokens integer not null check (input_tokens >= 0),
  output_tokens integer not null check (output_tokens >= 0),
  cache_read_tokens integer check (cache_read_tokens >= 0),
  stop_reason text check (length(stop_reason) between 1 and 40),
  audit_run_id uuid,
  intelligence_task_id uuid,
  created_at timestamptz not null default now(),
  check ((purpose = 'customer_api') = (funded_by = 'customer')),
  check ((purpose = 'first_scan') = (audit_run_id is not null)),
  check ((purpose = 'customer_api') = (intelligence_task_id is not null))
);
create index model_usage_receipts_user_time on public.model_usage_receipts (user_id, created_at desc);
create index model_usage_receipts_purpose_time on public.model_usage_receipts (purpose, created_at desc);
alter table public.model_usage_receipts enable row level security;
revoke all on public.model_usage_receipts from public, anon, authenticated;
grant select, insert on public.model_usage_receipts to service_role;

-- Anonymous scan log — stores only grade + issue count + hash of last 6 chars of URL
-- The project URL is hashed so no PII is stored
create table if not exists scan_logs (
  id              uuid        primary key default gen_random_uuid(),
  project_ref     text        not null,   -- last 6 chars of SHA-256(url), e.g. "a3f7c2"
  grade           text        not null check (grade in ('A','B','C','D','F')),
  issue_count     integer     not null default 0,
  critical_count  integer     not null default 0,
  created_at      timestamptz not null default now()
);

alter table scan_logs enable row level security;

-- Server (service role) can insert scan logs
-- We use service role from the API route, so no anon insert policy needed

-- Anyone can read scan logs (for the activity ticker)
create policy "Anyone can read scan logs"
  on scan_logs for select using (true);

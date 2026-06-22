-- Feedback from users about their audit experience
create table if not exists feedback (
  id          uuid        primary key default gen_random_uuid(),
  message     text        not null check (length(message) between 1 and 500),
  handle      text        not null default 'ANON',  -- display handle, e.g. FOUNDER_7x4
  created_at  timestamptz not null default now()
);

alter table feedback enable row level security;

-- Anyone can submit feedback
create policy "Anyone can insert feedback"
  on feedback for insert with check (true);

-- Anyone can read feedback (for the community terminal)
create policy "Anyone can read feedback"
  on feedback for select using (true);

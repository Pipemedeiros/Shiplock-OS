-- 046 — repositories and audit runs, for the GitHub-first MVP.
--
-- Two gaps this closes, both recorded in MVP-SPEC.md §7:
--
--   · One repository per account. `user_profiles.github_installation_id` is a
--     single column, so there was nowhere to record WHICH repositories a
--     customer chose, nothing to count a plan limit against, and no way for a
--     finding to say which repo it came from.
--   · No run record. The audit trace existed only as a log line, so "read this
--     run back, line by line" — the trust device the product is built on — had
--     no storage behind it.
--
-- Both tables are service-role only, the same posture as graph_facts: they hold
-- a map of the customer's private architecture and must never reach a browser.
-- The dashboard reads them through the service-role client in lib/, never
-- directly from the client.

create table if not exists public.repositories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  -- owner/name, as GitHub spells it. Unique per user so re-selecting is an
  -- upsert rather than a duplicate.
  full_name text not null,
  github_repo_id bigint,
  default_branch text not null default 'main',
  private boolean not null default true,
  language text,
  size_kb integer,
  -- Chosen by the customer during onboarding. A repo row can exist unselected:
  -- we list everything the installation can see, and audit only what was picked.
  selected boolean not null default false,
  last_audit_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, full_name)
);

create index if not exists repositories_user_selected_idx
  on public.repositories (user_id, selected);

create table if not exists public.audit_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid references public.repositories(id) on delete cascade,
  full_name text not null,
  commit_sha text,
  -- queued -> running -> complete | failed. A run that fails keeps its trace,
  -- because a failed run the customer can read is worth more than a silent one.
  status text not null default 'queued',
  trigger text not null default 'manual',
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  -- The full agent trace, one object per step: {time, label, note, found}.
  -- Stored rather than derived so a run reads identically a month later.
  trace jsonb not null default '[]'::jsonb,
  -- What the run inspected, so a thinner run cannot look like a cleaner one.
  files_read integer,
  entries_found integer,
  tables_found integer,
  findings_count integer not null default 0,
  -- Which surfaces this run could NOT reach, and why. Feeds the Coverage
  -- screen. Absent is not the same as clean.
  coverage jsonb not null default '[]'::jsonb,
  error text
);

create index if not exists audit_runs_user_started_idx
  on public.audit_runs (user_id, started_at desc);

-- Service-role only. RLS on with no policies denies every anon/authenticated
-- read, which is the intent: these tables describe the customer's architecture.
alter table public.repositories enable row level security;
alter table public.audit_runs enable row level security;

revoke all on public.repositories from anon, authenticated;
revoke all on public.audit_runs from anon, authenticated;

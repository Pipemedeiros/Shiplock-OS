-- Verified provider-project to ShipLock-repository associations.
-- Provider display names are evidence, not authorization. The composite
-- foreign key makes it impossible to associate one user's provider project
-- with another user's repository, even through the service-role client.

alter table public.repositories
  add constraint repositories_id_user_unique unique (id, user_id);

create table if not exists public.provider_repository_links (
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null check (provider ~ '^[a-z][a-z0-9_-]{0,31}$'),
  provider_project_id text not null,
  provider_project_name text not null,
  provider_repository text not null,
  provider_repository_id text,
  repository_id uuid not null,
  verification_method text not null check (verification_method = 'provider_git_link'),
  connection_fingerprint text not null check (connection_fingerprint ~ '^[a-f0-9]{64}$'),
  verified_at timestamptz not null,
  created_at timestamptz not null default now(),
  primary key (user_id, provider, provider_project_id),
  foreign key (repository_id, user_id)
    references public.repositories (id, user_id) on delete cascade
);

create index provider_repository_links_repository_idx
  on public.provider_repository_links (user_id, repository_id, provider);

alter table public.provider_repository_links enable row level security;
revoke all on public.provider_repository_links from anon, authenticated;

comment on table public.provider_repository_links is
  'Provider-issued project-to-repository links. A row is evidence of an explicit provider Git link, never a name-similarity guess.';

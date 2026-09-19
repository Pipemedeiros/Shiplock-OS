-- Customer-confirmed association, not provider-issued or deployment proof.
-- Requires migration 053's repositories (id, user_id) unique constraint.
create table public.database_repository_bindings (
  user_id uuid not null references auth.users(id) on delete cascade,
  repository_id uuid not null,
  collector text not null check (collector = 'postgres-direct'),
  connection_fingerprint text not null check (connection_fingerprint ~ '^[a-f0-9]{64}$'),
  github_installation_id text not null check (github_installation_id ~ '^[1-9][0-9]*$'),
  github_connected_at timestamptz not null,
  repository_full_name text not null,
  github_repo_id text check (github_repo_id ~ '^[1-9][0-9]*$'),
  confirmation_method text not null check (confirmation_method = 'customer_confirmed'),
  confirmed_at timestamptz not null check (confirmed_at >= github_connected_at),
  primary key (user_id, collector, repository_id),
  foreign key (repository_id, user_id) references public.repositories (id, user_id) on delete cascade
);

alter table public.database_repository_bindings enable row level security;
revoke all on public.database_repository_bindings from anon, authenticated;
grant select, insert, update, delete on public.database_repository_bindings to service_role;

comment on table public.database_repository_bindings is
  'Explicit customer association with configured direct Postgres. Credential/GitHub context must match at admission; this is not deployment verification.';

-- Extend explicit customer confirmation to separate Supabase access paths.
-- Does not convert existing direct confirmations or infer cross-transport links.
alter table public.database_repository_bindings
  add column project_ref text,
  add column endpoint_url text,
  drop constraint database_repository_bindings_collector_check,
  add constraint database_repository_bindings_collector_check
    check (collector in ('postgres-direct', 'supabase-management', 'supabase-scan')),
  add constraint database_repository_bindings_transport_identity_check check (
    (collector = 'postgres-direct' and project_ref is null and endpoint_url is null)
    or
    (collector = 'supabase-management' and project_ref is not null
      and project_ref ~ '^[a-z0-9-]+$' and length(project_ref) <= 63 and endpoint_url is null)
    or
    (collector = 'supabase-scan' and project_ref is not null
      and project_ref ~ '^[a-z0-9-]+$' and length(project_ref) <= 63
      and endpoint_url is not null and endpoint_url = 'https://' || project_ref || '.supabase.co')
  );

-- Preserve 054's tenant-bound FK, service-role grants and client RLS revocations.
comment on table public.database_repository_bindings is
  'Customer association with one configured database access path. Current transport/project/credential/GitHub identity must match; not deployment or security verification.';

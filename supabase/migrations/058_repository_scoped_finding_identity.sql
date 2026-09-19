-- The original active-finding key predates repositories. Once agent and graph
-- findings carry repository_id, `(user_id, source, finding_id)` makes the same
-- deterministic route id in two repositories collide. Migration 051's
-- `(repository_id, finding_id)` fixes retries but also merges different
-- collectors that happen to choose the same id.
--
-- Keep the legacy identity only for rows with no repository. Repository-bound
-- findings are unique inside user + source + repository, so neither another
-- repository nor another collector can suppress them.
drop index if exists public.deep_findings_active_uk;
drop index if exists public.deep_findings_open_per_repo_idx;

create unique index deep_findings_active_unscoped_uk
  on public.deep_findings (user_id, source, finding_id)
  where archived_at is null and repository_id is null;

create unique index deep_findings_active_repository_uk
  on public.deep_findings (user_id, source, repository_id, finding_id)
  where archived_at is null and repository_id is not null;

-- 051 — make an audit's finding write safely re-runnable.
--
-- persistFindings archived first and inserted second, as two separate
-- statements with no transaction and both errors discarded. A death between
-- them archived the previous findings and wrote no new ones, so the dashboard
-- read ZERO and rendered clean. That is the "absent is not clean" commitment
-- violated in the one place it matters most, and it was unguarded in
-- production.
--
-- The fix inverts the order: insert the fresh findings first, then archive what
-- the new run did not reproduce. A crash between the two now leaves BOTH the
-- old and the new visible — too much, never too little — and the next
-- successful run converges. Over-reporting is an annoyance; silently reporting
-- nothing is the failure that ends a customer relationship.
--
-- Inverting the order only works if the insert is safely re-runnable, which is
-- what this index buys: one live row per finding per repository, so a retry
-- after a partial write conflicts instead of duplicating.
--
-- PARTIAL, on `archived_at IS NULL`, on purpose. The same finding_id may recur
-- across months as a problem is fixed, returns, and is fixed again; each of
-- those is its own archived row and its own piece of history. Only one may be
-- OPEN at a time.
--
-- Scoped to agent findings with a repository. Rows from the older collectors
-- (source='github', 'zero-day', 'exposed-path') carry a null repository_id and
-- are untouched by this index and by the new write path.

create unique index if not exists deep_findings_open_per_repo_idx
  on public.deep_findings (repository_id, finding_id)
  where archived_at is null and repository_id is not null;

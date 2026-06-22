-- Add unique constraint on email that v1 was missing
ALTER TABLE user_profiles ADD CONSTRAINT user_profiles_email_unique UNIQUE (email);

-- Add preview_issues column to scan_history for paywall enforcement
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS preview_issues jsonb;
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS full_issues jsonb;

-- Rename existing issues column to full_issues if it exists
-- (run only if issues column exists, otherwise skip)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='scan_history' AND column_name='issues'
  ) THEN
    ALTER TABLE scan_history RENAME COLUMN issues TO full_issues;
  END IF;
END $$;

COMMENT ON COLUMN scan_history.full_issues IS 'All fixes included. Server-side only. Never return to free users.';
COMMENT ON COLUMN scan_history.preview_issues IS 'Titles and severities only. Safe to return to any caller.';

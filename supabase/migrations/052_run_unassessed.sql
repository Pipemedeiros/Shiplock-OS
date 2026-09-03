-- What the audit could NOT judge, as structured data on the run.
--
-- buildCoverage already writes a customer-facing NOTE about this, but a note is
-- prose: the Verified report needs the numbers themselves, and parsing them
-- back out of a sentence would break the first time the sentence is reworded.
--
-- Shape: { dataTouching, unassessed, dataUnreadable, reasons: { identity,
-- scope, signature }, sample: string[] } -- see lib/agent/unassessed.ts.
--
-- Null on every historical run, and the report renders that as "this run
-- predates the disclosure" rather than as zero. An absent measurement must
-- never read as a clean one.
alter table public.audit_runs
  add column if not exists unassessed jsonb;

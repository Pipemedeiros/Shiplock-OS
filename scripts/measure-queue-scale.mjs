// Local-only admission/fairness measurement. No environment credentials,
// network, provider API, model, or hosted database is used.
import { performance } from "node:perf_hooks";
import { readFile } from "node:fs/promises";
import { PGlite } from "../.cache/step23-sql/node_modules/@electric-sql/pglite/dist/index.js";

const accounts = Number(process.argv[2] ?? 50_000);
if (!Number.isInteger(accounts) || accounts < 1 || accounts > 100_000) {
  throw new Error("Account count must be an integer from 1 to 100000");
}

const db = new PGlite();
const started = performance.now();
try {
  await db.exec(`create schema auth;
    create table auth.users(id uuid primary key);
    create table public.user_profiles(id uuid primary key references auth.users(id),is_paid boolean not null default false);
    create function auth.uid() returns uuid language sql stable as 'select null::uuid';
    create role anon; create role authenticated; create role service_role bypassrls;
    grant usage on schema public to anon,authenticated,service_role;`);
  for (const file of [
    "021_phase2_github_deep_access.sql",
    "046_mvp_repos_and_runs.sql",
    "053_provider_repository_links.sql",
    "056_durable_jobs.sql",
    "059_audit_job_triggers.sql",
    "062_scheduled_audit_admission.sql",
  ]) {
    await db.exec(await readFile(new URL(`../supabase/migrations/${file}`, import.meta.url), "utf8"));
  }

  await db.query(`with identities as (
      select i, (
        substr(md5(i::text),1,8)||'-'||substr(md5(i::text),9,4)||'-4'||substr(md5(i::text),14,3)||
        '-8'||substr(md5(i::text),18,3)||'-'||substr(md5(i::text),21,12)
      )::uuid as id from generate_series(1,$1::integer) i
    ) insert into auth.users(id) select id from identities`, [accounts]);
  await db.exec(`insert into public.user_profiles(id,is_paid,github_installation_id)
    select id,true,row_number() over() from auth.users;
    insert into public.repositories(user_id,full_name,selected)
    select id,'tenant-'||row_number() over()||'/app',true from auth.users;`);
  const seededAt = performance.now();

  let calls = 0;
  let admitted = 0;
  let limited = true;
  while (limited) {
    const result = (await db.query(
      "select public.enqueue_due_repository_audits('2100-01-01','2026-09-21',true,1000) as result",
    )).rows[0].result;
    calls += 1;
    admitted += result.admitted;
    limited = result.limited;
  }
  const admittedAt = performance.now();

  const stored = (await db.query(`select
    (select count(*)::int from public.execution_jobs) as jobs,
    (select count(*)::int from public.audit_runs) as runs`)).rows[0];
  const claimed = [];
  for (let i = 0; i < 3; i++) {
    const row = (await db.query("select * from public.claim_execution_job('audit',120)")).rows[0];
    if (row) claimed.push(row);
  }
  const distinctClaimTenants = new Set(claimed.map((job) => job.user_id)).size;

  const duplicate = (await db.query(
    "select public.enqueue_due_repository_audits('2100-01-01','2026-09-21',true,1000) as result",
  )).rows[0].result;

  const stale = claimed[0];
  const stillRunning = claimed[1];
  await db.query("update public.execution_jobs set lease_until=now()-interval '1 second' where id=$1", [stale.id]);
  // Any claim pass performs lease recovery before selecting new work.
  await db.query("select * from public.claim_execution_job('audit',120)");
  const staleAdvanceRejected = (await db.query(
    "select public.advance_execution_job($1,$2,0,'succeeded') as ok",
    [stale.id, stale.lease_token],
  )).rows[0].ok === false;
  await db.query("update public.execution_jobs set run_after='2100-01-01' where status='queued'");
  await db.query("update public.execution_jobs set run_after=now()-interval '1 second' where id=$1", [stale.id]);
  await db.query("select public.advance_execution_job($1,$2,0,'succeeded')", [stillRunning.id, stillRunning.lease_token]);
  const replacement = (await db.query("select * from public.claim_execution_job('audit',120)")).rows[0];
  const finishedAt = performance.now();

  console.log(JSON.stringify({
    accounts,
    seedMs: Math.round(seededAt - started),
    admissionMs: Math.round(admittedAt - seededAt),
    totalMs: Math.round(finishedAt - started),
    admissionCalls: calls,
    admitted,
    stored,
    duplicateAdmission: duplicate,
    concurrentClaims: claimed.length,
    distinctClaimTenants,
    thirdAuditClaimBlockedByKindLimit: claimed.length === 2,
    staleAdvanceRejected,
    expiredJobReclaimed: replacement?.id === stale.id,
    replacementTokenChanged: replacement?.lease_token !== stale.lease_token,
  }, null, 2));
} finally {
  await db.close();
}

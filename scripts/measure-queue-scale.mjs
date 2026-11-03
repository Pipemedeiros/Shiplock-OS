// Local-only admission/fairness measurement. No environment credentials,
// network, provider API, model, or hosted database is used.
import { performance } from "node:perf_hooks";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";

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

  // 2026-09-23: mixed kinds. Migrations 070/077 widened the kind list
  // (repair, notification, intelligence); their other tables are not needed
  // here, so only the kind check is widened, to exactly 077's list.
  await db.exec(`alter table public.execution_jobs drop constraint execution_jobs_kind_check;
    alter table public.execution_jobs add constraint execution_jobs_kind_check
      check (kind in ('audit','source','monitor','dependency','graph','pr-check','notification','repair','intelligence'));
    update public.execution_jobs set status='succeeded', lease_token=null, lease_until=null, finished_at=now() where status='running';`);
  const otherKinds = ["source", "monitor", "dependency", "graph", "notification", "repair", "intelligence"];
  const perKind = Math.min(accounts, 5_000);
  for (const kind of otherKinds) {
    await db.query(`insert into public.execution_jobs(user_id, kind, deduplication_key)
      select id, $1, 'q4:'||$1 from auth.users order by id limit $2`, [kind, perKind]);
  }
  await db.query("update public.execution_jobs set run_after=now()-interval '1 second' where status='queued'");
  // Q4_KIND_INDEX=1 loads migration 089's kind-first ready index, to compare
  // against the pre-089 baseline on the same workload.
  const kindIndex = process.env.Q4_KIND_INDEX === "1";
  if (kindIndex) {
    await db.exec(await readFile(new URL("../supabase/migrations/089_job_claim_kind_index.sql", import.meta.url), "utf8"));
  }
  const mixedQueued = (await db.query("select count(*)::int as n from public.execution_jobs where status='queued'")).rows[0].n;
  const allKinds = ["audit", ...otherKinds];
  const latencies = [];
  let maxRunning = 0, maxPerKind = 0, maxPerTenant = 0, claims = 0, emptyClaims = 0;
  const rounds = 60;
  for (let round = 0; round < rounds; round++) {
    for (const kind of allKinds) {
      const t0 = performance.now();
      const row = (await db.query("select * from public.claim_execution_job($1,120)", [kind])).rows[0];
      latencies.push(performance.now() - t0);
      if (row) claims++; else emptyClaims++;
    }
    const shape = (await db.query(`select
      (select count(*)::int from public.execution_jobs where status='running') as running,
      (select coalesce(max(n),0)::int from (select count(*) n from public.execution_jobs where status='running' group by kind) k) as per_kind,
      (select coalesce(max(n),0)::int from (select count(*) n from public.execution_jobs where status='running' group by user_id) t) as per_tenant`)).rows[0];
    maxRunning = Math.max(maxRunning, shape.running);
    maxPerKind = Math.max(maxPerKind, shape.per_kind);
    maxPerTenant = Math.max(maxPerTenant, shape.per_tenant);
    // Workers finish everything they hold before the next round.
    await db.exec("update public.execution_jobs set status='succeeded', lease_token=null, lease_until=null, finished_at=now() where status='running'");
  }
  latencies.sort((a, b) => a - b);
  const pct = (p) => Math.round(latencies[Math.min(latencies.length - 1, Math.floor(p * latencies.length))] * 100) / 100;
  const mixed = {
    kindFirstReadyIndex: kindIndex, kinds: allKinds.length, queuedAtStart: mixedQueued, rounds, claimCalls: latencies.length, claims, emptyClaims,
    claimMsP50: pct(0.5), claimMsP95: pct(0.95), claimMsMax: Math.round(latencies[latencies.length - 1] * 100) / 100,
    maxRunningObserved: maxRunning, maxRunningPerKindObserved: maxPerKind, maxRunningPerTenantObserved: maxPerTenant,
    globalLimitHeld: maxRunning <= 8, perKindLimitHeld: maxPerKind <= 2, perTenantLimitHeld: maxPerTenant <= 1,
  };
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
    mixed,
  }, null, 2));
} finally {
  await db.close();
}

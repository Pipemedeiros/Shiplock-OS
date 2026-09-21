// Local PostgreSQL WASM checks. This never reads environment credentials or
// connects to a remote database. Install the pinned test runtime under .cache:
// npm install --prefix .cache/step23-sql --no-audit --no-fund --ignore-scripts --package-lock=false @electric-sql/pglite@0.3.14
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { PGlite } from "../.cache/step23-sql/node_modules/@electric-sql/pglite/dist/index.js";

const db = new PGlite();
let checks = 0;
async function check(name, test) { await test(); checks++; console.log(`PASS ${name}`); }
const u1 = "11111111-1111-4111-8111-111111111111", u2 = "22222222-2222-4222-8222-222222222222";
const r1 = "33333333-3333-4333-8333-333333333333", r2 = "44444444-4444-4444-8444-444444444444";
const r3 = "66666666-6666-4666-8666-666666666666";
try {
  await db.exec(`create schema auth;
    create table auth.users(id uuid primary key);
    create table public.user_profiles(id uuid primary key references auth.users(id));
    create function auth.uid() returns uuid language sql stable as 'select null::uuid';
    create role anon; create role authenticated; create role service_role bypassrls;
    grant usage on schema public to anon,authenticated,service_role;`);
  for (const file of ["021_phase2_github_deep_access.sql", "046_mvp_repos_and_runs.sql", "047_agent_findings.sql", "051_findings_idempotent_persist.sql", "053_provider_repository_links.sql", "054_database_repository_bindings.sql", "055_supabase_repository_bindings.sql", "056_durable_jobs.sql", "057_atomic_audit_findings.sql", "058_repository_scoped_finding_identity.sql", "059_audit_job_triggers.sql"]) {
    await db.exec(await readFile(new URL(`../supabase/migrations/${file}`, import.meta.url), "utf8"));
  }
  await db.query("insert into auth.users values ($1),($2)", [u1,u2]);
  await db.query("insert into public.repositories(id,user_id,full_name,selected) values($1,$2,'acme/one',true),($3,$4,'acme/two',true),($5,$2,'acme/three',true)", [r1,u1,r2,u2,r3]);
  // Match Supabase's service-role base-table privileges in this minimal fixture.
  await db.exec("grant select on public.repositories to service_role; set role service_role");
  const enqueue = async (u,r,k) => (await db.query("select public.enqueue_execution_job($1,$2,'monitor',$3) as id",[u,r,k])).rows[0].id;
  const claim = async () => (await db.query("select * from public.claim_execution_job('monitor',120)")).rows[0];
  const advance = async (job,checkpoint,outcome) => (await db.query("select public.advance_execution_job($1,$2,$3,$4) as ok",[job.id,job.lease_token,checkpoint,outcome])).rows[0].ok;
  let first, second, auditJob, auditRun, auditToken;
  await check("tenant repository FK/enqueue validation", async () => {
    await assert.rejects(enqueue(u1,r2,"cross-tenant"));
  });
  await check("idempotent enqueue", async () => {
    first = await enqueue(u1,r1,"one"); assert.equal(await enqueue(u1,r1,"one"),first);
    second = await enqueue(u2,r2,"two");
  });
  let a,b;
  await check("different tenants can run while duplicate claims cannot", async () => {
    a = await claim(); b = await claim(); assert.notEqual(a.id,b.id); assert.equal(await claim(),undefined);
    assert.deepEqual(new Set([a.id,b.id]),new Set([first,second]));
  });
  await check("wrong fencing token cannot complete work", async () => {
    assert.equal(await advance({...a,lease_token:u2},0,"succeeded"),false);
  });
  await check("checkpoint cannot skip stages or move backward", async () => {
    assert.equal(await advance(a,2,"checkpoint"),false);
    assert.equal(await advance(a,1,"checkpoint"),true);
    assert.equal(await advance(a,0,"heartbeat"),false);
  });
  await check("expired worker is rejected and rescheduled with a new token", async () => {
    await db.query("update public.execution_jobs set lease_until=now()-interval '1 second' where id=$1",[a.id]);
    assert.equal(await advance(a,1,"succeeded"),false);
    await claim();
    await db.query("update public.execution_jobs set run_after=now()-interval '1 second' where id=$1",[a.id]);
    const replacement=await claim(); assert.equal(replacement.id,a.id); assert.notEqual(replacement.lease_token,a.lease_token);
    assert.equal(replacement.checkpoint,1); assert.equal(replacement.attempts,2);
    assert.equal(await advance(a,1,"succeeded"),false); a=replacement;
  });
  await check("completion is terminal and retry cannot change it", async () => {
    assert.equal(await advance(a,1,"succeeded"),true); assert.equal(await advance(a,1,"retry"),false);
  });
  await check("maximum attempts reaches dead state", async () => {
    await db.query("update public.execution_jobs set attempts=5 where id=$1",[b.id]);
    assert.equal(await advance(b,0,"retry"),true);
    assert.equal((await db.query("select status from public.execution_jobs where id=$1",[b.id])).rows[0].status,"dead");
  });
  await check("client roles cannot read jobs or invoke queue RPCs", async () => {
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.execution_jobs"));
    await assert.rejects(db.query("select public.claim_execution_job('audit',120)"));
    await db.exec("reset role; set role anon");
    await assert.rejects(db.query("select * from public.database_repository_bindings"));
    await assert.rejects(db.query("select * from public.provider_repository_links"));
    await assert.rejects(db.query("select public.enqueue_execution_job($1,$2,'audit','x')",[u1,r1]));
    await assert.rejects(db.query("select * from public.enqueue_repository_audit($1,$2,'x')",[u1,r1]));
    await db.exec("reset role; set role service_role");
  });
  await check("audit enqueue atomically creates one idempotent customer-visible run", async () => {
    const one=(await db.query("select * from public.enqueue_repository_audit($1,$2,'manual-one')",[u1,r1])).rows[0];
    const two=(await db.query("select * from public.enqueue_repository_audit($1,$2,'manual-one')",[u1,r1])).rows[0];
    assert.deepEqual(two,one);
    await db.exec("reset role");
    const linked=(await db.query("select j.audit_run_id,r.status,r.full_name,r.trigger from public.execution_jobs j join public.audit_runs r on r.id=j.audit_run_id where j.id=$1",[one.job_id])).rows[0];
    assert.deepEqual(linked,{audit_run_id:one.run_id,status:"queued",full_name:"acme/one",trigger:"manual"});
    const pr=(await db.query("select * from public.enqueue_repository_audit($1,$2,'pr-head-one','pull_request')",[u1,r1])).rows[0];
    const prTrigger=(await db.query("select trigger from public.audit_runs where id=$1",[pr.run_id])).rows[0].trigger;
    assert.equal(prTrigger,"pull_request");
    await assert.rejects(db.query("select * from public.enqueue_repository_audit($1,$2,'pr-head-one','manual')",[u1,r1]));
    await assert.rejects(db.query("select * from public.enqueue_repository_audit($1,$2,'bad-trigger','deploy')",[u1,r1]));
    await db.exec("set role service_role");
    await assert.rejects(db.query("select * from public.enqueue_repository_audit($1,$2,'cross')",[u1,r2]));
    await assert.rejects(db.query("select public.enqueue_execution_job($1,$2,'audit','generic')",[u1,r1]));
    const claimed=(await db.query("select * from public.claim_execution_job('audit',120)")).rows[0];
    auditJob=claimed.id; auditRun=claimed.audit_run_id; auditToken=claimed.lease_token;
    await db.exec("reset role");
    assert.equal((await db.query("select audit_execution_token from public.audit_runs where id=$1",[auditRun])).rows[0].audit_execution_token,auditToken);
    await db.exec("set role service_role");
  });
  const binding = `insert into public.database_repository_bindings(user_id,repository_id,collector,connection_fingerprint,github_installation_id,github_connected_at,repository_full_name,confirmation_method,confirmed_at,project_ref,endpoint_url)
    values($1,$2,$3,repeat('a',64),'42','2026-09-01','acme/one','customer_confirmed','2026-09-02',$4,$5)`;
  await check("binding FK prevents cross-tenant rows with service-role access", async () => {
    await assert.rejects(db.query(binding,[u1,r2,"postgres-direct",null,null]));
  });
  await check("transport shapes are enforced in SQL", async () => {
    await db.query(binding,[u1,r1,"postgres-direct",null,null]);
    await db.query(binding,[u1,r1,"supabase-management","project-a",null]);
    await db.query(binding,[u1,r1,"supabase-scan","project-a","https://project-a.supabase.co"]);
    await assert.rejects(db.query("update public.database_repository_bindings set endpoint_url='https://other.supabase.co' where collector='supabase-scan'"));
    await assert.rejects(db.query("update public.database_repository_bindings set project_ref=null where collector='supabase-management'"));
  });
  await db.exec("reset role");
  const run = "55555555-5555-4555-8555-555555555555";
  await db.query("insert into public.audit_runs(id,user_id,repository_id,full_name,status) values($1,$2,$3,'acme/one','running')",[run,u1,r1]);
  const finding = (id) => ({id,severity:"CRITICAL",confidence:"inferred",title:id,consequence:"evidence",attackClass:"missing_authentication",entry:"/api/data",file:"app/api/data/route.ts",fixKind:"pr",claims:[]});
  const persist = async (findings,preserve=false,user=u1,repo=r1,runId=run,jobId=null,token=null) => db.query("select public.persist_repository_findings($1,$2,$3,$4,$5,$6,$7)",[user,repo,runId,JSON.stringify(findings),preserve,jobId,token]);
  const active = async () => (await db.query("select finding_id from public.deep_findings where archived_at is null order by finding_id")).rows.map(row=>row.finding_id);
  await check("historical PostgREST conflict target cannot infer the partial index", async () => {
    await assert.rejects(db.query("insert into public.deep_findings(user_id,repository_id,source,finding_id,severity,title,consequence) values($1,$2,'agent','bad','INFO','bad','bad') on conflict(repository_id,finding_id) do nothing",[u1,r1]), /no unique or exclusion constraint/);
  });
  await check("atomic findings insert is idempotent with the actual partial index", async () => {
    await persist([finding("old")]); await persist([finding("old")]); assert.deepEqual(await active(),["old"]);
  });
  await check("partial empty and partial new findings retain old evidence", async () => {
    await persist([],true); assert.deepEqual(await active(),["old"]);
    await persist([finding("new")],true); assert.deepEqual(await active(),["new","old"]);
  });
  await check("complete run retires only its tenant/repository/agent rows", async () => {
    await db.query("insert into public.deep_findings(user_id,repository_id,source,finding_id,severity,title,consequence) values($1,$2,'zero-day','dependency','WARNING','dep','dep'),($3,$4,'agent','other','WARNING','other','other')",[u1,r1,u2,r2]);
    await persist([finding("new")]); assert.deepEqual(await active(),["dependency","new","other"]);
  });
  await check("failed insertion rolls back retirement", async () => {
    await assert.rejects(persist([{...finding("broken"),title:null}]));
    assert.deepEqual(await active(),["dependency","new","other"]);
  });
  await check("failure during archival rolls back inserted replacements", async () => {
    await db.exec("create function public.fail_archive_test() returns trigger language plpgsql as $$ begin raise exception 'archive failed'; end $$; create trigger fail_archive_test before update on public.deep_findings for each row execute function public.fail_archive_test()");
    await assert.rejects(persist([finding("replacement")]));
    assert.deepEqual(await active(),["dependency","new","other"]);
    await db.exec("drop trigger fail_archive_test on public.deep_findings; drop function public.fail_archive_test()");
  });
  await check("a failed audit transaction can be rerun and findings can recur", async () => {
    await persist([finding("replacement")]); await persist([finding("new")]);
    assert.deepEqual(await active(),["dependency","new","other"]);
    assert.equal((await db.query("select count(*)::int as n from public.deep_findings where finding_id='new'")).rows[0].n,2);
  });
  await check("finding persistence refuses cross-tenant run/repository and proven claims", async () => {
    await assert.rejects(persist([],false,u1,r2)); await assert.rejects(persist([],false,u2,r2));
    await assert.rejects(persist([{...finding("invented"),confidence:"proven"}]));
    await db.exec("set role authenticated"); await assert.rejects(persist([])); await db.exec("reset role");
  });
  await check("audit finding writes are fenced by the current unexpired worker lease", async () => {
    await db.query("update public.audit_runs set status='running' where id=$1",[auditRun]);
    await assert.rejects(persist([finding("fenced")],true,u1,r1,auditRun,auditJob,u2));
    await persist([finding("fenced")],true,u1,r1,auditRun,auditJob,auditToken);
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'dead') as ok",[auditJob,auditToken])).rows[0].ok,true);
    const terminal=(await db.query("select status,audit_execution_token,error from public.audit_runs where id=$1",[auditRun])).rows[0];
    assert.deepEqual(terminal,{status:"failed",audit_execution_token:null,error:"Audit execution stopped before completion."});
  });
  await check("the same deterministic finding id remains independent per repository", async () => {
    const otherRun = "77777777-7777-4777-8777-777777777777";
    await db.query("insert into public.audit_runs(id,user_id,repository_id,full_name,status) values($1,$2,$3,'acme/three','running')",[otherRun,u1,r3]);
    await persist([finding("same-route")],false,u1,r1,run);
    await persist([finding("same-route")],false,u1,r3,otherRun);
    const rows = await db.query("select repository_id from public.deep_findings where source='agent' and finding_id='same-route' and archived_at is null order by repository_id");
    assert.deepEqual(rows.rows.map((row) => row.repository_id),[r1,r3]);
  });
  console.log(`${checks} SQL checks passed. Single-connection PostgreSQL WASM; multi-session contention and hosted Supabase remain unverified.`);
} finally { await db.close(); }

// Local PostgreSQL WASM checks. This never reads environment credentials or
// connects to a remote database. Install the pinned test runtime under .cache:
// npm install --prefix .cache/step23-sql --no-audit --no-fund --ignore-scripts --package-lock=false @electric-sql/pglite@0.3.14
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
    create table public.user_profiles(id uuid primary key references auth.users(id),is_paid boolean not null default false);
    create function auth.uid() returns uuid language sql stable as 'select null::uuid';
    create role anon; create role authenticated; create role service_role bypassrls;
    grant usage on schema public to anon,authenticated,service_role;`);
  for (const file of ["008_monitoring.sql", "021_phase2_github_deep_access.sql", "022_phase2_vercel_env_audit.sql", "032_monitored_app_url.sql", "034_supabase_mgmt_connection.sql", "036_source_scan_coalescing.sql", "039_graph_facts.sql", "043_finding_correlation.sql", "044_hourly_pass_fairness.sql", "045_direct_postgres_connection.sql", "046_mvp_repos_and_runs.sql", "047_agent_findings.sql", "050_runtime_graph_facts.sql", "051_findings_idempotent_persist.sql", "053_provider_repository_links.sql", "054_database_repository_bindings.sql", "055_supabase_repository_bindings.sql", "056_durable_jobs.sql", "057_atomic_audit_findings.sql", "058_repository_scoped_finding_identity.sql", "059_audit_job_triggers.sql", "060_atomic_repository_selection.sql", "061_github_install_handshake.sql", "062_scheduled_audit_admission.sql", "063_durable_pull_request_checks.sql", "064_fenced_source_collection.sql", "065_fenced_dependency_rechecks.sql", "066_durable_provider_monitoring.sql"]) {
    await db.exec(await readFile(new URL(`../supabase/migrations/${file}`, import.meta.url), "utf8"));
  }
  // 2D: a connection that predates epochs must keep its current identity.
  const legacy = "55555555-5555-4555-8555-555555555555";
  await db.query("insert into auth.users values ($1)", [legacy]);
  await db.query("insert into public.user_profiles(id,vercel_access_token_encrypted,supabase_mgmt_token_encrypted,postgres_dsn_encrypted,monitored_anon_key_encrypted) values($1,'v-cipher','m-cipher','p-cipher','  ')", [legacy]);
  await db.exec(await readFile(new URL("../supabase/migrations/067_connection_epochs.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/068_fenced_provider_results.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/069_manual_monitor_trigger.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/070_repair_action_receipts.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/071_pull_request_reviews.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/072_pull_request_fix_receipts.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/073_pull_request_alerts.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/074_intelligence_tasks.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/075_intelligence_retention.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/076_intelligence_connections.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/077_intelligence_scans.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/079_intelligence_credentials.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/080_ai_fix_receipts.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/081_first_scan_credit.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/082_manual_audit_quota.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/031_api_tokens.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/083_click_quotas.sql", import.meta.url), "utf8"));
  await db.exec(await readFile(new URL("../supabase/migrations/084_repair_merge.sql", import.meta.url), "utf8"));
  for (const file of ["025_traffic_protection.sql", "026_session_traffic.sql", "027_traffic_alert_action.sql", "085_traffic_sites.sql", "086_traffic_observations.sql"]) {
    await db.exec(await readFile(new URL(`../supabase/migrations/${file}`, import.meta.url), "utf8"));
  }
  await db.query("insert into auth.users values ($1),($2)", [u1,u2]);
  await db.query("insert into public.user_profiles(id) values($1),($2)", [u1,u2]);
  await check("connection epochs backfill the existing fingerprint and ignore blank credentials", async () => {
    const hex = (v) => createHash("sha256").update(v).digest("hex");
    const row = (await db.query("select vercel_connection_epoch v, supabase_mgmt_connection_epoch m, postgres_connection_epoch p, supabase_endpoint_connection_epoch e from public.user_profiles where id=$1",[legacy])).rows[0];
    assert.deepEqual(row,{v:hex("v-cipher"),m:hex("m-cipher"),p:hex("p-cipher"),e:null});
  });
  await check("a credential and its connection epoch must be present together", async () => {
    await assert.rejects(db.query("update public.user_profiles set vercel_access_token_encrypted='x' where id=$1",[u1]));
    await assert.rejects(db.query("update public.user_profiles set vercel_access_token_encrypted=null where id=$1",[legacy]));
    await assert.rejects(db.query("update public.user_profiles set postgres_connection_epoch='not-hex' where id=$1",[legacy]));
    await db.query("update public.user_profiles set monitored_anon_key_encrypted='k',supabase_endpoint_connection_epoch=$2 where id=$1",[u1,"a".repeat(64)]);
    await db.query("update public.user_profiles set monitored_anon_key_encrypted=null,supabase_endpoint_connection_epoch=null where id=$1",[u1]);
  });
  await check("re-encrypting or refreshing a credential keeps its epoch", async () => {
    const before=(await db.query("select supabase_mgmt_connection_epoch e from public.user_profiles where id=$1",[legacy])).rows[0].e;
    await db.query("update public.user_profiles set supabase_mgmt_token_encrypted='m-cipher-refreshed' where id=$1",[legacy]);
    assert.equal((await db.query("select supabase_mgmt_connection_epoch e from public.user_profiles where id=$1",[legacy])).rows[0].e,before);
  });
  // Remove the legacy credentials so later admission checks see only their fixtures.
  await db.query("update public.user_profiles set vercel_access_token_encrypted=null,vercel_connection_epoch=null,supabase_mgmt_token_encrypted=null,supabase_mgmt_connection_epoch=null,postgres_dsn_encrypted=null,postgres_connection_epoch=null where id=$1",[legacy]);
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
  await check("repository selection replacement is atomic and preserves GitHub metadata", async () => {
    const selection = JSON.stringify([{full_name:"acme/one",github_repo_id:"123456",default_branch:"develop",private:false}]);
    const rows = await db.query("select * from public.replace_selected_repositories($1,$2::jsonb)",[u1,selection]);
    assert.deepEqual(rows.rows,[{id:r1,full_name:"acme/one"}]);
    const stored=(await db.query("select full_name,github_repo_id::text,default_branch,private,selected from public.repositories where user_id=$1 order by full_name",[u1])).rows;
    assert.deepEqual(stored,[
      {full_name:"acme/one",github_repo_id:"123456",default_branch:"develop",private:false,selected:true},
      {full_name:"acme/three",github_repo_id:null,default_branch:"main",private:true,selected:false},
    ]);
    await assert.rejects(db.query("select * from public.replace_selected_repositories($1,$2::jsonb)",[u1,JSON.stringify([
      {full_name:"acme/one",default_branch:"main",private:true},
      {full_name:"acme/one",default_branch:"main",private:true},
    ])]));
    assert.equal((await db.query("select selected from public.repositories where id=$1",[r1])).rows[0].selected,true);
  });
  await check("client roles cannot replace repository scope", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select * from public.replace_selected_repositories($1,'[]'::jsonb)",[u1]));
    await db.exec("reset role");
  });
  await check("GitHub installation completion requires one current tenant handshake", async () => {
    const nonce="a".repeat(64);
    assert.equal((await db.query("select public.begin_github_install($1,$2) as ok",[u1,nonce])).rows[0].ok,true);
    assert.equal((await db.query("select public.complete_github_install($1,$2,42) as ok",[u1,"b".repeat(64)])).rows[0].ok,false);
    assert.equal((await db.query("select public.complete_github_install($1,$2,42) as ok",[u1,nonce])).rows[0].ok,true);
    assert.equal((await db.query("select github_installation_id from public.user_profiles where id=$1",[u1])).rows[0].github_installation_id,42);
    assert.equal((await db.query("select selected from public.repositories where id=$1",[r1])).rows[0].selected,false);
    assert.equal((await db.query("select public.complete_github_install($1,$2,42) as ok",[u1,nonce])).rows[0].ok,false);
  });
  await check("client roles cannot begin or complete a GitHub installation", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select public.begin_github_install($1,$2)",[u1,"c".repeat(64)]));
    await assert.rejects(db.query("select public.complete_github_install($1,$2,42)",[u1,"c".repeat(64)]));
    await db.exec("reset role");
  });
  await check("daily scheduled admission is bounded, idempotent, and preserves its trigger", async () => {
    await db.query("update public.user_profiles set is_paid=true where id=$1",[u1]);
    await db.query("select * from public.replace_selected_repositories($1,$2::jsonb)",[u1,JSON.stringify([
      {full_name:"acme/one",github_repo_id:"123456",default_branch:"develop",private:false},
    ])]);
    const args=["2100-01-01T00:00:00Z","2026-09-21",true,100];
    const firstAdmission=(await db.query("select public.enqueue_due_repository_audits($1,$2,$3,$4) as result",args)).rows[0].result;
    const retry=(await db.query("select public.enqueue_due_repository_audits($1,$2,$3,$4) as result",args)).rows[0].result;
    assert.deepEqual(firstAdmission,{eligible:1,admitted:1,failed:0,limited:false});
    assert.deepEqual(retry,{eligible:0,admitted:0,failed:0,limited:false});
    const scheduled=(await db.query("select count(*)::int as count,min(r.trigger) as trigger from public.execution_jobs j join public.audit_runs r on r.id=j.audit_run_id where j.deduplication_key=$1",[`scheduled:${r1}:2026-09-21`])).rows[0];
    assert.deepEqual(scheduled,{count:1,trigger:"scheduled"});
  });
  await check("client roles cannot schedule repository audits", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select public.enqueue_due_repository_audits(now(),'2026-09-21',false,100)"));
    await db.exec("reset role");
  });
  await check("pull-request check admission is typed and idempotent", async () => {
    const key=`pr-check:acme/one:${"a".repeat(40)}`;
    const one=(await db.query("select public.enqueue_pull_request_check($1,$2,$3,7,$4) as id",[u1,r1,key,"A".repeat(40)])).rows[0].id;
    const two=(await db.query("select public.enqueue_pull_request_check($1,$2,$3,7,$4) as id",[u1,r1,key,"a".repeat(40)])).rows[0].id;
    assert.equal(two,one);
    const stored=(await db.query("select j.kind,c.user_id,c.repository_id,c.pull_request_number,c.head_sha from public.execution_jobs j join public.pull_request_jobs c on c.job_id=j.id where j.id=$1",[one])).rows[0];
    assert.deepEqual(stored,{kind:"pr-check",user_id:u1,repository_id:r1,pull_request_number:7,head_sha:"a".repeat(40)});
    await assert.rejects(db.query("select public.enqueue_pull_request_check($1,$2,$3,8,$4)",[u1,r1,key,"a".repeat(40)]));
    await assert.rejects(db.query("select public.enqueue_pull_request_check($1,$2,$3,7,$4)",[u1,r1,key,"b".repeat(40)]));
    await assert.rejects(db.query("select public.enqueue_pull_request_check($1,$2,'bad',7,'short')",[u1,r1]));
  });
  await check("client roles cannot read or admit pull-request checks", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select * from public.pull_request_jobs"));
    await assert.rejects(db.query("select public.enqueue_pull_request_check($1,$2,'x',7,$3)",[u1,r1,"a".repeat(40)]));
    await db.exec("reset role");
  });
  let sourceJob, sourceToken;
  const sourceSnapshot = () => ({
    repositoryId:r1,providerRepositoryId:"123456",repositoryFullName:"acme/one",installationId:"42",ref:"develop",
    recordedAt:new Date().toISOString(),completeness:"partial",filesAttempted:1,filesRead:1,
    routes:[],liveFiles:[],hasEntryPoints:false,dependencies:[{name:"left-pad",version:"1.0.0"}],
  });
  const sourceFinding = [{finding_id:"acme/one::github:test",severity:"WARNING",title:"Source evidence",consequence:"Review it."}];
  await check("scheduled source admission is repository-scoped and idempotent", async () => {
    const args=["2100-01-01T00:00:00Z","2026-09-22",100];
    const admitted=(await db.query("select public.enqueue_due_repository_sources($1,$2,$3) as result",args)).rows[0].result;
    const retry=(await db.query("select public.enqueue_due_repository_sources($1,$2,$3) as result",args)).rows[0].result;
    assert.deepEqual(admitted,{eligible:1,admitted:1,failed:0,limited:false});
    assert.deepEqual(retry,{eligible:0,admitted:0,failed:0,limited:false});
    const claimed=(await db.query("select * from public.claim_execution_job('source',120)")).rows[0];
    sourceJob=claimed.id;sourceToken=claimed.lease_token;
    assert.equal(claimed.repository_id,r1);
  });
  await check("source facts and findings commit atomically under the current lease", async () => {
    const result=(await db.query("select public.persist_repository_source($1,$2,$3,$4,$5::jsonb,$6::jsonb) as result",[
      u1,r1,sourceJob,sourceToken,JSON.stringify(sourceSnapshot()),JSON.stringify(sourceFinding),
    ])).rows[0].result;
    assert.deepEqual(result,{total:1,newCount:1,resolvedCount:0});
    const stored=(await db.query("select facts->'repositories'->0->>'repositoryId' as repository_id from public.graph_facts where user_id=$1 and collector='source'",[u1])).rows[0];
    assert.equal(stored.repository_id,r1);
    const findingRow=(await db.query("select repository_id from public.deep_findings where source='github' and finding_id=$1 and archived_at is null",[sourceFinding[0].finding_id])).rows[0];
    assert.equal(findingRow.repository_id,r1);
    assert.ok((await db.query("select last_source_scan_at is not null as stamped from public.repositories where id=$1",[r1])).rows[0].stamped);
    await assert.rejects(db.query("select public.persist_repository_source($1,$2,$3,$4,$5::jsonb,'[]'::jsonb)",[
      u1,r1,sourceJob,u2,JSON.stringify(sourceSnapshot()),
    ]));
  });
  await check("partial source absence never retires prior evidence", async () => {
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[sourceJob,sourceToken])).rows[0].ok,true);
    const next=(await db.query("select public.enqueue_execution_job($1,$2,'source','source-recheck') as id",[u1,r1])).rows[0].id;
    const claimed=(await db.query("select * from public.claim_execution_job('source',120)")).rows[0];
    assert.equal(claimed.id,next);
    await db.query("select public.persist_repository_source($1,$2,$3,$4,$5::jsonb,'[]'::jsonb)",[
      u1,r1,claimed.id,claimed.lease_token,JSON.stringify(sourceSnapshot()),
    ]);
    assert.equal((await db.query("select count(*)::int as count from public.deep_findings where source='github' and finding_id=$1 and archived_at is null",[sourceFinding[0].finding_id])).rows[0].count,1);
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[claimed.id,claimed.lease_token])).rows[0].ok,true);
  });
  await check("graph findings are repository-scoped and fenced", async () => {
    const graphId=(await db.query("select public.enqueue_execution_job($1,$2,'graph','graph-test') as id",[u1,r1])).rows[0].id;
    const graph=(await db.query("select * from public.claim_execution_job('graph',120)")).rows[0];
    assert.equal(graph.id,graphId);
    const sourceRevision=(await db.query("select snapshot->>'recordedAt' as revision from public.graph_facts facts cross join lateral jsonb_array_elements(facts.facts->'repositories') snapshot where facts.user_id=$1 and snapshot->>'repositoryId'=$2",[u1,r1])).rows[0].revision;
    const finding=[{finding_id:"path:test",severity:"CRITICAL",title:"Attack path",consequence:"Close either side.",surfaces:["source","db"]}];
    await assert.rejects(db.query("select public.persist_repository_graph($1,$2,$3,$4,$5,$6::jsonb,false)",[
      u1,r1,graph.id,u2,sourceRevision,JSON.stringify(finding),
    ]));
    await assert.rejects(db.query("select public.persist_repository_graph($1,$2,$3,$4,$5,$6::jsonb,false)",[
      u1,r1,graph.id,graph.lease_token,"2026-09-22T00:00:00.000Z",JSON.stringify(finding),
    ]));
    const result=(await db.query("select public.persist_repository_graph($1,$2,$3,$4,$5,$6::jsonb,false) as result",[
      u1,r1,graph.id,graph.lease_token,sourceRevision,JSON.stringify(finding),
    ])).rows[0].result;
    assert.deepEqual(result,{total:1,newCount:1,resolvedCount:0});
    const stored=(await db.query("select repository_id,correlation from public.deep_findings where source='graph' and finding_id='path:test' and archived_at is null")).rows[0];
    assert.equal(stored.repository_id,r1);assert.deepEqual(stored.correlation,{surfaces:["source","db"],proven:false});
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[graph.id,graph.lease_token])).rows[0].ok,true);
  });
  await check("daily dependency admission is scoped and idempotent", async () => {
    const args=["2026-09-23",100];
    const admitted=(await db.query("select public.enqueue_due_repository_dependencies($1,$2) as result",args)).rows[0].result;
    const retry=(await db.query("select public.enqueue_due_repository_dependencies($1,$2) as result",args)).rows[0].result;
    assert.deepEqual(admitted,{eligible:1,admitted:1,failed:0,limited:false});
    assert.deepEqual(retry,{eligible:0,admitted:0,failed:0,limited:false});
  });
  await check("dependency findings commit only under the current source revision and lease", async () => {
    const dependency=(await db.query("select * from public.claim_execution_job('dependency',120)")).rows[0];
    const revision=(await db.query("select snapshot->>'recordedAt' as revision from public.graph_facts facts cross join lateral jsonb_array_elements(facts.facts->'repositories') snapshot where facts.user_id=$1 and snapshot->>'repositoryId'=$2",[u1,r1])).rows[0].revision;
    const finding=[{finding_id:"acme/one::github:dep:left-pad:GHSA-test",severity:"CRITICAL",title:"Dependency RCE",consequence:"Upgrade.",package_name:"left-pad",version:"1.0.0",vuln_id:"GHSA-test",cve_id:"CVE-2026-2"}];
    await assert.rejects(db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,$5,$6::jsonb)",[
      u1,r1,dependency.id,u2,revision,JSON.stringify(finding),
    ]));
    await assert.rejects(db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,$5,$6::jsonb)",[
      u1,r1,dependency.id,dependency.lease_token,"2026-09-22T00:00:00.000Z",JSON.stringify(finding),
    ]));
    await db.query("update public.repositories set default_branch='main' where id=$1",[r1]);
    await assert.rejects(db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,$5,$6::jsonb)",[
      u1,r1,dependency.id,dependency.lease_token,revision,JSON.stringify(finding),
    ]));
    await db.query("update public.repositories set default_branch='develop' where id=$1",[r1]);
    await db.query("update public.user_profiles set github_installation_id=99 where id=$1",[u1]);
    assert.equal((await db.query("select last_source_scan_at is null as stale from public.repositories where id=$1",[r1])).rows[0].stale,true);
    await assert.rejects(db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,$5,$6::jsonb)",[
      u1,r1,dependency.id,dependency.lease_token,revision,JSON.stringify(finding),
    ]));
    await db.query("update public.user_profiles set github_installation_id=42 where id=$1",[u1]);
    await db.query("update public.repositories set last_source_scan_at=now() where id=$1",[r1]);
    const result=(await db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,$5,$6::jsonb) as result",[
      u1,r1,dependency.id,dependency.lease_token,revision,JSON.stringify(finding),
    ])).rows[0].result;
    assert.deepEqual(result,{total:1,newCount:1,resolvedCount:0});
    assert.equal((await db.query("select count(*)::int as count from public.deep_findings where repository_id=$1 and source='zero-day' and finding_id=$2 and archived_at is null",[r1,finding[0].finding_id])).rows[0].count,1);
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[dependency.id,dependency.lease_token])).rows[0].ok,true);
  });
  await check("repository reselection invalidates source freshness", async () => {
    assert.ok((await db.query("select last_source_scan_at is not null as fresh from public.repositories where id=$1",[r1])).rows[0].fresh);
    await db.query("select * from public.replace_selected_repositories($1,$2::jsonb)",[u1,JSON.stringify([
      {full_name:"acme/one",github_repo_id:"123456",default_branch:"develop",private:false},
    ])]);
    assert.equal((await db.query("select last_source_scan_at is null as stale from public.repositories where id=$1",[r1])).rows[0].stale,true);
  });
  await check("client roles cannot invoke source, graph, or dependency persistence", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select public.enqueue_due_repository_sources(now(),'2026-09-22',100)"));
    await assert.rejects(db.query("select public.persist_repository_source($1,$2,$3,$4,'{}'::jsonb,'[]'::jsonb)",[u1,r1,sourceJob,sourceToken]));
    await assert.rejects(db.query("select public.persist_repository_graph($1,$2,$3,$4,'2026-09-22T00:00:00.000Z','[]'::jsonb,false)",[u1,r1,sourceJob,sourceToken]));
    await assert.rejects(db.query("select public.enqueue_due_repository_dependencies('2026-09-23',100)"));
    await assert.rejects(db.query("select public.persist_repository_dependency_findings($1,$2,$3,$4,'2026-09-22T00:00:00.000Z','[]'::jsonb)",[u1,r1,sourceJob,sourceToken]));
    await db.exec("reset role");
  });
  await check("provider-only monitoring admission is bounded, typed, and idempotent", async () => {
    await db.query("update public.user_profiles set monitoring_enabled=false,postgres_dsn_encrypted='cipher',postgres_connection_epoch=$2 where id=$1",[u1,"b".repeat(64)]);
    const args=["scheduled_48h","2100-01-01T00:00:00Z","2026-09-22",100];
    const admitted=(await db.query("select public.enqueue_due_monitoring_passes($1,$2,$3,$4) as result",args)).rows[0].result;
    const retry=(await db.query("select public.enqueue_due_monitoring_passes($1,$2,$3,$4) as result",args)).rows[0].result;
    assert.deepEqual(admitted,{eligible:1,admitted:1,failed:0,limited:false});
    assert.deepEqual(retry,{eligible:0,admitted:0,failed:0,limited:false});
    const stored=(await db.query("select j.id,j.repository_id,c.user_id,c.trigger_source from public.execution_jobs j join public.monitoring_job_context c on c.job_id=j.id where j.user_id=$1 and j.deduplication_key like 'scheduled-monitor:%'",[u1])).rows[0];
    assert.deepEqual(stored,{id:stored.id,repository_id:null,user_id:u1,trigger_source:"scheduled_48h"});
    await assert.rejects(db.query("select public.enqueue_monitoring_job($1,'deploy',$2)",[
      u1,`scheduled-monitor:scheduled_48h:${u1}:2026-09-22`,
    ]));
    await assert.rejects(db.query("select public.enqueue_monitoring_job($1,'deploy','no-provider')",[u2]));
  });
  await check("notification admission is fenced to one live monitor result",async()=>{
    const monitor=(await db.query("select * from public.claim_execution_job('monitor',120)")).rows[0];
    const findings=[{id:"rls:orders",severity:"CRITICAL",title:"Open orders",consequence:"Anyone can read them."}];
    await assert.rejects(db.query("select public.enqueue_monitoring_notifications($1,$2,$3,$4::jsonb)",[u1,monitor.id,u2,JSON.stringify(findings)]));
    const notification=(await db.query("select public.enqueue_monitoring_notifications($1,$2,$3,$4::jsonb) as id",[u1,monitor.id,monitor.lease_token,JSON.stringify(findings)])).rows[0].id;
    assert.equal((await db.query("select kind from public.execution_jobs where id=$1",[notification])).rows[0].kind,"notification");
    assert.deepEqual((await db.query("select user_id,findings from public.monitoring_notification_batches where job_id=$1",[notification])).rows[0],{user_id:u1,findings});
    assert.equal((await db.query("select public.enqueue_monitoring_notifications($1,$2,$3,$4::jsonb) as id",[u1,monitor.id,monitor.lease_token,JSON.stringify(findings)])).rows[0].id,notification);
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[monitor.id,monitor.lease_token])).rows[0].ok,true);
  });
  await check("hourly fairness receipt requires its current live lease",async()=>{
    await db.query("update public.user_profiles set monitoring_enabled=true,monitored_project_url='https://x.supabase.co',monitored_anon_key_encrypted='cipher',supabase_endpoint_connection_epoch=$2 where id=$1",[u1,"c".repeat(64)]);
    await db.query("select public.enqueue_monitoring_job($1,'hourly','hourly-receipt-test')",[u1]);
    const hourly=(await db.query("select * from public.claim_execution_job('monitor',120)")).rows[0];
    assert.equal((await db.query("select public.stamp_hourly_monitor_attempt($1,$2,$3) as ok",[u1,hourly.id,u2])).rows[0].ok,false);
    assert.equal((await db.query("select public.stamp_hourly_monitor_attempt($1,$2,$3) as ok",[u1,hourly.id,hourly.lease_token])).rows[0].ok,true);
    assert.equal((await db.query("select last_hourly_pass_at is not null as stamped from public.user_profiles where id=$1",[u1])).rows[0].stamped,true);
    assert.equal((await db.query("select public.advance_execution_job($1,$2,0,'succeeded') as ok",[hourly.id,hourly.lease_token])).rows[0].ok,true);
  });
  await check("client roles cannot read or admit monitoring jobs", async () => {
    await db.exec("set role authenticated");
    await assert.rejects(db.query("select * from public.monitoring_job_context"));
    await assert.rejects(db.query("select * from public.monitoring_notification_batches"));
    await assert.rejects(db.query("select public.enqueue_monitoring_job($1,'deploy','x')",[u1]));
    await assert.rejects(db.query("select public.enqueue_due_monitoring_passes('scheduled_48h',now(),'x',100)"));
    await assert.rejects(db.query("select public.enqueue_monitoring_notifications($1,$2,$3,'[]'::jsonb)",[u1,u2,u1]));
    await assert.rejects(db.query("select public.stamp_hourly_monitor_attempt($1,$2,$3)",[u1,u2,u1]));
    await db.exec("reset role");
  });
  // 3F-C2c-1: provider results commit only under a live monitor lease and the
  // connection identity they were collected under.
  await db.exec("reset role; grant select on public.deep_findings, public.graph_facts to service_role");
  const pEpoch = "a".repeat(64);
  await db.query("update public.user_profiles set postgres_dsn_encrypted='p2',postgres_connection_epoch=$2,monitored_app_url='https://app.example.com' where id=$1",[legacy,pEpoch]);
  const monitorJob = async (key) => {
    const id=(await db.query("select public.enqueue_execution_job($1,null,'monitor',$2) as id",[legacy,key])).rows[0].id;
    const token=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes' where id=$1 returning lease_token",[id])).rows[0].lease_token;
    return { id, token };
  };
  const providerFinding = (id, severity="CRITICAL") => ({ id, severity, title:`t ${id}`, consequence:`c ${id}` });
  const persistProvider = (job, transport, identity, facts, findings, retire, unread=[]) => db.query(
    "select public.persist_provider_monitor_result($1,$2,$3,$4,$5,$6,$7,$8,$9) as created",
    [legacy, job.id, job.token, transport, identity, facts===null?null:JSON.stringify(facts), JSON.stringify(findings), retire, JSON.stringify(unread)]);
  const activeProvider = async (source) => (await db.query("select finding_id from public.deep_findings where user_id=$1 and source=$2 and archived_at is null order by finding_id",[legacy,source])).rows.map((r)=>r.finding_id);
  await db.exec("set role service_role");
  await check("provider results commit facts and new findings atomically and idempotently", async () => {
    const job = await monitorJob("c2c-commit");
    const created = (await persistProvider(job,"postgres-direct",pEpoch,{policies:[]},[providerFinding("rls:a"),providerFinding("rls:b")],true)).rows[0].created;
    assert.deepEqual(created.map((f)=>f.id).sort(),["rls:a","rls:b"]);
    assert.deepEqual((await persistProvider(job,"postgres-direct",pEpoch,{policies:[]},[providerFinding("rls:a"),providerFinding("rls:b")],true)).rows[0].created,[]);
    assert.deepEqual(await activeProvider("policy"),["rls:a","rls:b"]);
    const facts=(await db.query("select facts from public.graph_facts where user_id=$1 and collector='db'",[legacy])).rows[0].facts;
    assert.deepEqual(facts.policies,[]); assert.equal(facts._evidence.fields.policies.completeness,"unknown");
    // A later result from another transport merges without erasing this one.
    await persistProvider(job,"postgres-direct",pEpoch,{inventory:{tables:1}},[providerFinding("rls:a"),providerFinding("rls:b")],false);
    const merged=(await db.query("select facts from public.graph_facts where user_id=$1 and collector='db'",[legacy])).rows[0].facts;
    assert.deepEqual(merged.policies,[]); assert.deepEqual(merged.inventory,{tables:1});
    assert.deepEqual(Object.keys(merged._evidence.fields).sort(),["inventory","policies"]);
  });
  await check("provider results retire only re-checked findings and keep unread ones", async () => {
    const job = await monitorJob("c2c-retire");
    await persistProvider(job,"postgres-direct",pEpoch,null,[],true,["rls:b"]);
    assert.deepEqual(await activeProvider("policy"),["rls:b"]);
    await persistProvider(job,"postgres-direct",pEpoch,null,[providerFinding("rls:c")],false);
    assert.deepEqual(await activeProvider("policy"),["rls:b","rls:c"]);
  });
  await check("stale, expired, or foreign leases commit nothing", async () => {
    const job = await monitorJob("c2c-lease");
    await assert.rejects(persistProvider({...job,token:u2},"postgres-direct",pEpoch,null,[providerFinding("rls:x")],false));
    await db.exec("reset role");
    await db.query("update public.execution_jobs set lease_until=now()-interval '1 second' where id=$1",[job.id]);
    await db.exec("set role service_role");
    await assert.rejects(persistProvider(job,"postgres-direct",pEpoch,null,[providerFinding("rls:x")],false));
    assert.equal((await activeProvider("policy")).includes("rls:x"),false);
  });
  await check("a reconnect after collection commits nothing", async () => {
    const job = await monitorJob("c2c-reconnect");
    await assert.rejects(persistProvider(job,"postgres-direct","b".repeat(64),{policies:[1]},[providerFinding("rls:y")],true));
    assert.deepEqual(await activeProvider("policy"),["rls:b","rls:c"]);
    await assert.rejects(persistProvider(job,"app-surface","https://other.example.com",null,[providerFinding("exposed:git_exposed")],true));
    const created=(await persistProvider(job,"app-surface","https://app.example.com",null,[providerFinding("exposed:git_exposed")],true)).rows[0].created;
    assert.deepEqual(created.map((f)=>f.id),["exposed:git_exposed"]);
  });
  await check("provider result payloads are bounded and typed", async () => {
    const job = await monitorJob("c2c-shape");
    await assert.rejects(persistProvider(job,"github",pEpoch,null,[],false));
    await assert.rejects(persistProvider(job,"postgres-direct",pEpoch,[],[],false));
    await assert.rejects(persistProvider(job,"postgres-direct",pEpoch,null,[{id:"x",severity:"LOUD",title:"t",consequence:"c"}],false));
    await assert.rejects(persistProvider(job,"app-surface","https://app.example.com",{x:1},[],false));
  });
  await check("a customer rescan is admitted as a manual monitor job", async () => {
    const id=(await db.query("select public.enqueue_monitoring_job($1,'manual','manual:postgres-direct:1') as id",[legacy])).rows[0].id;
    assert.equal(id,(await db.query("select public.enqueue_monitoring_job($1,'manual','manual:postgres-direct:1') as id",[legacy])).rows[0].id);
    await db.exec("reset role");
    assert.equal((await db.query("select trigger_source from public.monitoring_job_context where job_id=$1",[id])).rows[0].trigger_source,"manual");
    await db.exec("set role service_role");
    await assert.rejects(db.query("select public.enqueue_monitoring_job($1,'manual','manual:none')",[u2]));
    await assert.rejects(db.query("select public.enqueue_monitoring_job($1,'bogus','manual:bad')",[legacy]));
  });
  // 3F-C2d: every PR write is one clicked, receipted, lease-fenced job.
  const requestRepair = (user, repo, key, action="finding-fix-pr", finding="rls:orders", edited=null) => db.query(
    "select public.request_repair_action($1,$2,$3,$4,$5,$6) as receipt",[user,repo,action,finding,edited,key]);
  await check("a repair click creates one receipt and one queued repair job", async () => {
    const receipt=(await requestRepair(u1,r1,"click-1")).rows[0].receipt;
    assert.equal((await requestRepair(u1,r1,"click-1")).rows[0].receipt,receipt);
    await assert.rejects(requestRepair(u1,r1,"click-1","finding-fix-pr","rls:other"));
    await assert.rejects(requestRepair(u1,r2,"click-x"));
    await assert.rejects(requestRepair(u1,r1,"click-y","merge-pr"));
    await assert.rejects(requestRepair(u1,r1,"click-z","finding-fix-pr",null));
    await assert.rejects(requestRepair(u1,r1,"click-w","risk-fix-pr","agent:x","edited text"));
    assert.ok((await requestRepair(u1,r1,"click-v","risk-fix-pr","agent:x")).rows[0].receipt);
    await db.exec("reset role");
    const row=(await db.query("select r.status,r.finding_id,j.kind,j.status as job_status from public.repair_action_receipts r join public.execution_jobs j on j.id=r.job_id where r.id=$1",[receipt])).rows[0];
    assert.deepEqual(row,{status:"queued",finding_id:"rls:orders",kind:"repair",job_status:"queued"});
    await db.exec("set role service_role");
  });
  await check("only the live repair lease can record an outcome", async () => {
    const receipt=(await requestRepair(u1,r1,"click-2")).rows[0].receipt;
    await db.exec("reset role");
    const job=(await db.query("select job_id from public.repair_action_receipts where id=$1",[receipt])).rows[0].job_id;
    const token=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes' where id=$1 returning lease_token",[job])).rows[0].lease_token;
    await db.exec("set role service_role");
    const complete=(t,status,url,number,failure=null)=>db.query("select public.complete_repair_action($1,$2,$3,$4,$5,$6,$7) as ok",[u1,job,t,status,url,number,failure]);
    assert.equal((await complete(u2,"opened","https://github.com/acme/one/pull/7",7)).rows[0].ok,false);
    await assert.rejects(complete(token,"opened","https://evil.example.com/pull/7",7));
    await assert.rejects(complete(token,"failed",null,null,"not-a-code"));
    await assert.rejects(requestRepair(u1,r1,"click-dep","dependency-bump-pr","github:dep:x"));
    const depReceipt=(await requestRepair(u1,r1,"click-dep","dependency-bump-pr",null)).rows[0].receipt;
    await db.exec("reset role");
    const depJob=(await db.query("select job_id from public.repair_action_receipts where id=$1",[depReceipt])).rows[0].job_id;
    const depToken=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes' where id=$1 returning lease_token",[depJob])).rows[0].lease_token;
    await db.exec("set role service_role");
    assert.equal((await db.query("select public.complete_repair_action($1,$2,$3,'failed',null,null,'no_changes') as ok",[u1,depJob,depToken])).rows[0].ok,true);
    assert.equal((await complete(token,"uncertain",null,null,"delivery_unconfirmed")).rows[0].ok,true);
    assert.equal((await complete(token,"opened","https://github.com/acme/one/pull/7",7)).rows[0].ok,true);
    assert.equal((await complete(token,"failed",null,null,"github_rejected")).rows[0].ok,false);
    await db.exec("reset role");
    assert.deepEqual((await db.query("select status,pr_url,pr_number from public.repair_action_receipts where id=$1",[receipt])).rows[0],
      {status:"opened",pr_url:"https://github.com/acme/one/pull/7",pr_number:7});
    await db.exec("set role service_role");
  });
  await check("client roles cannot request, complete, or read repair receipts", async () => {
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.repair_action_receipts"));
    await assert.rejects(requestRepair(u1,r1,"click-client"));
    await assert.rejects(db.query("select public.complete_repair_action($1,$1,$1,'opened',null,null,null)",[u1]));
    await db.exec("reset role; set role service_role");
  });
  // 8B-1: each PR check stores what it found, fenced to its own job.
  await check("a pull-request review is stored once per head commit under the check lease", async () => {
    const key="review-pr-9";
    const job=(await db.query("select public.enqueue_pull_request_check($1,$2,$3,9,$4) as id",[u1,r1,key,"c".repeat(40)])).rows[0].id;
    await db.exec("reset role");
    const token=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes' where id=$1 returning lease_token",[job])).rows[0].lease_token;
    await db.exec("set role service_role");
    const review=(over={})=>JSON.stringify({pullRequestNumber:9,headSha:"c".repeat(40),headRef:"feature/orders",headRepository:"acme/one",
      sameRepository:true,title:"Add orders API",url:"https://github.com/acme/one/pull/9",verdict:"block",coverageComplete:true,
      findings:[{id:"diff:unscoped-query",severity:"CRITICAL",title:"Orders query is not scoped",detail:"d",file:"app/api/orders/route.ts",evidence:"e"}],...over});
    const persist=(t,body)=>db.query("select public.persist_pull_request_review($1,$2,$3,$4) as id",[u1,job,t,body]);
    const id=(await persist(token,review())).rows[0].id;
    assert.equal((await persist(token,review({verdict:"warn"}))).rows[0].id,id);
    await assert.rejects(persist(u2,review()));
    await assert.rejects(persist(token,review({pullRequestNumber:10})));
    await assert.rejects(persist(token,review({headSha:"d".repeat(40)})));
    await assert.rejects(persist(token,review({verdict:"clean"})));
    await assert.rejects(persist(token,review({url:"https://evil.example.com/pull/9"})));
    await assert.rejects(persist(token,review({findings:[{id:"x",severity:"LOUD",title:"t",detail:"d",file:"f",evidence:"e"}]})));
    await db.exec("reset role");
    const row=(await db.query("select verdict,head_ref,same_repository,jsonb_array_length(findings) n from public.pull_request_reviews where id=$1",[id])).rows[0];
    assert.deepEqual(row,{verdict:"warn",head_ref:"feature/orders",same_repository:true,n:1});
    // 9A: the blocking store admitted exactly one alert job for this PR head,
    // and re-storing the same head never adds another.
    const alerts=(await db.query("select n.job_id,j.kind from public.pull_request_notifications n join public.execution_jobs j on j.id=n.job_id where n.review_id=$1",[id])).rows;
    assert.equal(alerts.length,1); assert.equal(alerts[0].kind,"notification");
    await db.exec("set role service_role");
  });
  await check("a fix-before-merge click binds to the caller's own same-repository review", async () => {
    await db.exec("reset role");
    const review=(await db.query("select id from public.pull_request_reviews where user_id=$1 and pull_request_number=9",[u1])).rows[0].id;
    const fork=(await db.query("insert into public.pull_request_reviews(user_id,repository_id,pull_request_number,head_sha,head_ref,same_repository,verdict,coverage_complete,findings) values($1,$2,10,$3,'patch-1',false,'block',true,$4) returning id",
      [u1,r1,"e".repeat(40),JSON.stringify([{id:"diff:x",severity:"CRITICAL",title:"t",detail:"d",file:"f",evidence:"e"}])])).rows[0].id;
    await db.exec("set role service_role");
    const ask=(key,finding,reviewId,repo=r1,user=u1)=>db.query("select public.request_repair_action($1,$2,'pr-fix-pr',$3,null,$4,$5) as receipt",[user,repo,finding,key,reviewId]);
    const receipt=(await ask("pr-fix-1","diff:unscoped-query",review)).rows[0].receipt;
    assert.equal((await ask("pr-fix-1","diff:unscoped-query",review)).rows[0].receipt,receipt);
    await assert.rejects(ask("pr-fix-2","diff:not-in-review",review));
    await assert.rejects(ask("pr-fix-3","diff:x",fork));
    await assert.rejects(ask("pr-fix-4","diff:unscoped-query",null));
    await assert.rejects(ask("pr-fix-5","diff:unscoped-query",review,r2,u2));
    await assert.rejects(db.query("select public.request_repair_action($1,$2,'risk-fix-pr','agent:x',null,'pr-fix-6',$3)",[u1,r1,review]));
    await db.exec("reset role");
    assert.equal((await db.query("select review_id from public.repair_action_receipts where id=$1",[receipt])).rows[0].review_id,review);
    await db.exec("set role service_role");
  });
  await check("a pull request that only warns admits no alert", async () => {
    const job=(await db.query("select public.enqueue_pull_request_check($1,$2,'review-pr-11',11,$3) as id",[u1,r1,"f".repeat(40)])).rows[0].id;
    await db.exec("reset role");
    const token=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes' where id=$1 returning lease_token",[job])).rows[0].lease_token;
    await db.exec("set role service_role");
    const id=(await db.query("select public.persist_pull_request_review($1,$2,$3,$4) as id",[u1,job,token,JSON.stringify({pullRequestNumber:11,headSha:"f".repeat(40),verdict:"warn",coverageComplete:true,findings:[]})])).rows[0].id;
    await db.exec("reset role");
    assert.equal((await db.query("select count(*)::int n from public.pull_request_notifications where review_id=$1",[id])).rows[0].n,0);
    await db.exec("set role service_role");
  });
  await check("client roles cannot read or write pull-request reviews", async () => {
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.pull_request_notifications"));
    await assert.rejects(db.query("select * from public.pull_request_reviews"));
    await assert.rejects(db.query("select public.persist_pull_request_review($1,$1,$1,'{}'::jsonb)",[u1]));
    await db.exec("reset role; set role service_role");
  });
  // 10B-1: durable customer-intelligence tasks bound to tenant, selected
  // repository, commit, and the GitHub installation they were created under.
  const sources=JSON.stringify([{path:"next.config.ts",sourceHash:"1".repeat(64)}]);
  const newTask=(key,user=u1,repo=r1,minutes=10)=>db.query(
    "select public.create_intelligence_task($1,$2,$3,'codex','Propose the source-map fix.',$4,now()+make_interval(mins=>$5),$6) as id",
    [user,repo,"a".repeat(40),sources,minutes,key]);
  const submit=(task,status,digest,user=u1)=>db.query("select public.submit_intelligence_result($1,$2,$3,$4,$5) as outcome",
    [user,task,status,JSON.stringify({status,summary:"s"}),digest]);
  await check("an intelligence task is created once per key for the caller's selected repository", async () => {
    await db.exec("reset role; update public.user_profiles set github_installation_id=42,github_connected_at=now()-interval '1 day' where id=$1".replace("$1",`'${u1}'`)+"; set role service_role");
    await db.query("select public.approve_intelligence_connection($1,'codex','weekly','daily',50000,1000000)",[u1]);
    const id=(await newTask("intel-1")).rows[0].id;
    assert.equal((await newTask("intel-1")).rows[0].id,id);
    await assert.rejects(newTask("intel-2",u1,r2));
    await assert.rejects(newTask("intel-3",u1,r1,24*60+5));
    await assert.rejects(db.query("select public.create_intelligence_task($1,$2,$3,'codex','x',$4,now()+interval '5 minutes','intel-4')",
      [u1,r1,"a".repeat(40),JSON.stringify([{path:"../.env",sourceHash:"1".repeat(64)}])]));
    await assert.rejects(db.query("select public.create_intelligence_task($1,$2,$3,'gpt','x',$4,now()+interval '5 minutes','intel-5')",[u1,r1,"a".repeat(40),sources]));
  });
  await check("results are owner-only, final once, and exact replays return the same outcome", async () => {
    const id=(await newTask("intel-6")).rows[0].id;
    await assert.rejects(submit(id,"proposal_received","2".repeat(64),u2));
    assert.equal((await submit(id,"proposal_received","2".repeat(64))).rows[0].outcome,"accepted");
    assert.equal((await submit(id,"proposal_received","2".repeat(64))).rows[0].outcome,"replayed");
    await assert.rejects(submit(id,"needs_human","3".repeat(64)));
    await assert.rejects(submit(id,"applied","4".repeat(64)));
  });
  await check("expiry, reinstall, deselection, and cancellation stop new results but keep accepted ones readable", async () => {
    const accepted=(await newTask("intel-7")).rows[0].id;
    await submit(accepted,"needs_human","5".repeat(64));
    const expiring=(await newTask("intel-8")).rows[0].id;
    const reinstall=(await newTask("intel-9")).rows[0].id;
    const cancelled=(await newTask("intel-10")).rows[0].id;
    assert.equal((await db.query("select public.cancel_intelligence_task($1,$2) as ok",[u1,cancelled])).rows[0].ok,true);
    await assert.rejects(submit(cancelled,"unavailable","6".repeat(64)));
    await db.exec("reset role");
    await db.query("update public.intelligence_tasks set expires_at=now()-interval '1 second' where id in ($1,$2)",[expiring,accepted]);
    await db.exec("set role service_role");
    await assert.rejects(submit(expiring,"unavailable","7".repeat(64)));
    assert.equal((await submit(accepted,"needs_human","5".repeat(64))).rows[0].outcome,"replayed");
    await db.exec("reset role");
    await db.query("update public.user_profiles set github_connected_at=now() where id=$1",[u1]);
    await db.exec("set role service_role");
    await assert.rejects(submit(reinstall,"unavailable","8".repeat(64)));
    await db.exec("reset role");
    assert.deepEqual((await db.query("select status,result_digest from public.intelligence_tasks where id=$1",[accepted])).rows[0],{status:"needs_human",result_digest:"5".repeat(64)});
    await db.exec("set role service_role");
  });
  await check("intelligence results and dead tasks are purged on a bounded schedule", async () => {
    await db.exec("reset role; update public.user_profiles set github_connected_at=now()-interval '2 days' where id='"+u1+"'; set role service_role");
    const fresh=(await newTask("intel-ret-1")).rows[0].id;
    await submit(fresh,"needs_human","a".repeat(64));
    const old=(await newTask("intel-ret-2")).rows[0].id;
    await submit(old,"needs_human","b".repeat(64));
    const dead=(await newTask("intel-ret-3")).rows[0].id;
    const pending=(await newTask("intel-ret-4")).rows[0].id;
    await db.exec("reset role");
    await db.query("update public.intelligence_tasks set completed_at=now()-interval '31 days' where id=$1",[old]);
    await db.query("update public.intelligence_tasks set expires_at=now()-interval '2 days' where id=$1",[dead]);
    await db.exec("set role service_role");
    assert.ok((await db.query("select public.purge_intelligence_tasks() as n")).rows[0].n>=2);
    await db.exec("reset role");
    const left=(await db.query("select id from public.intelligence_tasks where id = any($1)",[[fresh,old,dead,pending]])).rows.map((r)=>r.id).sort();
    assert.deepEqual(left,[fresh,pending].sort());
    await db.exec("set role service_role");
  });
  // 10B-2b: one pre-approved intelligence connection per account.
  const approve=(host="claude-code",deep="weekly",pr="daily",run=50000,month=1000000,user=u1)=>db.query(
    "select public.approve_intelligence_connection($1,$2,$3,$4,$5,$6) as at",[user,host,deep,pr,run,month]);
  await check("an account pre-approves its intelligence host, cadence, and budgets once", async () => {
    await approve();
    await approve("codex","off","every_2_days",20000,500000);
    await db.exec("reset role");
    const rows=(await db.query("select host,deep_scan_cadence,pr_scan_cadence,run_token_budget,revoked_at from public.intelligence_connections where user_id=$1",[u1])).rows;
    assert.deepEqual(rows,[{host:"codex",deep_scan_cadence:"off",pr_scan_cadence:"every_2_days",run_token_budget:20000,revoked_at:null}]);
    await db.exec("set role service_role");
    await assert.rejects(approve("gemini"));
    await assert.rejects(approve("codex","hourly"));
    await assert.rejects(approve("codex","weekly","hourly"));
    // PR scans are tied to PRs; there is no per-deploy cadence.
    await assert.rejects(approve("codex","weekly","per_deploy"));
    await assert.rejects(approve("codex","weekly","daily",500,1000000));
    await assert.rejects(approve("codex","weekly","daily",50000,10000));
  });
  await check("tasks need an active approval for that host, and switching hosts cancels the old host's work", async () => {
    await approve("codex");
    const old=(await newTask("intel-gate-1")).rows[0].id;
    await assert.rejects(db.query("select public.create_intelligence_task($1,$2,$3,'claude-code','x',$4,now()+interval '10 minutes','intel-gate-2')",[u1,r1,"a".repeat(40),sources]), /intelligence not approved/);
    await approve("claude-code");
    await db.exec("reset role");
    assert.equal((await db.query("select status from public.intelligence_tasks where id=$1",[old])).rows[0].status,"cancelled");
    await db.exec("set role service_role");
    await assert.rejects(newTask("intel-gate-3"), /intelligence not approved/);
    // An exact replay returns the same, now cancelled, task: no new work.
    assert.equal((await newTask("intel-gate-1")).rows[0].id,old);
  });
  await check("revoking the connection cancels pending tasks and a chatgpt host can hold tasks", async () => {
    await approve("chatgpt");
    const pending=(await db.query("select public.create_intelligence_task($1,$2,$3,'chatgpt','x',$4,now()+interval '10 minutes','intel-rev-1') as id",[u1,r1,"a".repeat(40),sources])).rows[0].id;
    assert.ok((await db.query("select public.revoke_intelligence_connection($1) as n",[u1])).rows[0].n>=1);
    await db.exec("reset role");
    assert.equal((await db.query("select status from public.intelligence_tasks where id=$1",[pending])).rows[0].status,"cancelled");
    assert.ok((await db.query("select revoked_at from public.intelligence_connections where user_id=$1",[u1])).rows[0].revoked_at);
    await db.exec("set role service_role");
    await assert.rejects(db.query("select public.create_intelligence_task($1,$2,$3,'chatgpt','x',$4,now()+interval '10 minutes','intel-rev-2')",[u1,r1,"a".repeat(40),sources]), /intelligence not approved/);
  });
  await check("the monthly budget stops new tasks once agent-reported usage reaches it", async () => {
    await approve("codex","off","off",1000,10000);
    const t=(await newTask("intel-budget-1")).rows[0].id;
    const usage=()=>db.query("select public.intelligence_month_usage($1) as n",[u1]).then((x)=>Number(x.rows[0].n));
    assert.equal(await usage(),0);
    await db.query("select public.submit_intelligence_result($1,$2,'unavailable',$3,$4)",
      [u1,t,JSON.stringify({status:"unavailable",usage:{inputTokens:6000,outputTokens:5000}}),"7".repeat(64)]);
    assert.equal(await usage(),11000);
    await assert.rejects(newTask("intel-budget-2"), /intelligence budget exhausted/);
    await approve("codex","off","off",1000,50000);
    assert.ok((await newTask("intel-budget-3")).rows[0].id);
  });
  // 10B-2c: approved cadences admit identity-only intelligence scan jobs.
  const due=(at="2026-09-23T12:00:00Z")=>db.query("select public.enqueue_due_intelligence_scans($1::timestamptz,100) as a",[at]).then((x)=>x.rows[0].a);
  const scans=()=>db.query("reset role").then(()=>db.query("select s.scan,s.pull_request_number as pr,s.head_sha as head,j.kind from public.intelligence_scan_jobs s join public.execution_jobs j on j.id=s.job_id where s.user_id=$1 order by s.scan,s.pull_request_number",[u1])).then(async (x)=>{await db.exec("set role service_role"); return x.rows;});
  const head="c".repeat(40);
  await check("a weekly deep scan is admitted once per selected repository per ISO week", async () => {
    await approve("codex","weekly","off");
    assert.deepEqual(await due(),{eligible:1,admitted:1,failed:0,limited:false});
    assert.deepEqual(await due("2026-09-24T12:00:00Z"),{eligible:0,admitted:0,failed:0,limited:false});
    assert.deepEqual(await scans(),[{scan:"deep",pr:null,head:null,kind:"intelligence"}]);
    assert.equal((await due("2026-09-30T12:00:00Z")).admitted,1);
  });
  await check("windowed PR scans cover every PR check admitted in the window, at its latest head, even if the check failed", async () => {
    await approve("codex","off","daily");
    await db.exec("reset role");
    // PR 5: two admitted checks (the later one never produced a review); PR 6: outside the window.
    for (const [pr,sha,at,status] of [[5,"a".repeat(40),"2026-10-01T08:00:00Z","succeeded"],[5,head,"2026-10-01T09:00:00Z","dead"],[6,"a".repeat(40),"2026-09-20T09:00:00Z","succeeded"]]) {
      const job=(await db.query("insert into public.execution_jobs(user_id,repository_id,kind,deduplication_key,status,created_at) values ($1,$2,'pr-check',$3,$4,$5) returning id",[u1,r1,`pr-window:${pr}:${sha}`,status,at])).rows[0].id;
      await db.query("insert into public.pull_request_jobs(job_id,user_id,repository_id,pull_request_number,head_sha) values ($1,$2,$3,$4,$5)",[job,u1,r1,pr,sha]);
    }
    await db.exec("set role service_role");
    assert.equal((await due("2026-10-01T12:00:00Z")).admitted,1);
    assert.equal((await due("2026-10-01T13:00:00Z")).admitted,0);
    assert.deepEqual((await scans()).filter((x)=>x.scan==="pr"),[{scan:"pr",pr:5,head,kind:"intelligence"}]);
  });
  await check("every-PR scans are admitted only under that cadence, idempotently", async () => {
    const pr=(n)=>db.query("select public.enqueue_pull_request_intelligence($1,$2,$3,$4) as id",[u1,r1,n,head]).then((x)=>x.rows[0].id);
    assert.equal(await pr(7),null);
    await approve("codex","off","every_pr");
    const id=await pr(7);
    assert.ok(id);
    assert.equal(await pr(7),id);
    await assert.rejects(db.query("select public.enqueue_pull_request_intelligence($1,$2,7,'nothex')",[u1,r1]));
    await db.query("select public.revoke_intelligence_connection($1)",[u1]);
    assert.equal(await pr(8),null);
    assert.equal((await due("2026-10-08T12:00:00Z")).eligible,0);
  });
  // 10B-2e: one encrypted customer model key per account, service-only.
  await check("a customer API key is stored only as ciphertext with a 4-character hint and a fresh epoch", async () => {
    const save=(hint,epoch="e".repeat(64))=>db.query("insert into public.intelligence_credentials(user_id,provider,key_encrypted,key_hint,epoch) values ($1,'anthropic','v1:'||repeat('c',40),$2,$3) on conflict (user_id) do update set key_encrypted=excluded.key_encrypted,key_hint=excluded.key_hint,epoch=excluded.epoch,created_at=now()",[u1,hint,epoch]);
    await save("Ab_9");
    await save("Zz-1","f".repeat(64));
    await db.exec("reset role");
    assert.deepEqual((await db.query("select key_hint,epoch from public.intelligence_credentials where user_id=$1",[u1])).rows,[{key_hint:"Zz-1",epoch:"f".repeat(64)}]);
    await db.exec("set role service_role");
    await assert.rejects(save("toolong"));
    await assert.rejects(save("Ab_9","nothex"));
    await assert.rejects(db.query("insert into public.intelligence_credentials(user_id,provider,key_encrypted,key_hint,epoch) values ($1,'openai','v1:'||repeat('c',40),'Ab_9',$2)",[u2,"e".repeat(64)]));
  });
  await check("an API-mode task can be claimed for a model call exactly once", async () => {
    await approve("api","off","off",50000,1000000);
    const t=(await db.query("select public.create_intelligence_task($1,$2,$3,'api','x',$4,now()+interval '10 minutes','intel-claim-1') as id",[u1,r1,"a".repeat(40),sources])).rows[0].id;
    const claim=(task,user=u1)=>db.query("select public.claim_api_intelligence_task($1,$2) as ok",[user,task]).then((x)=>x.rows[0].ok);
    assert.equal(await claim(t,u2),false);
    assert.equal(await claim(t),true);
    assert.equal(await claim(t),false);
    const codex=(await (async()=>{await approve("codex");return newTask("intel-claim-2");})()).rows[0].id;
    assert.equal(await claim(codex),false);
  });
  await check("a clicked AI fix is receipted only for the owner's answered proposal with edits (10B-3b)", async () => {
    await approve("codex","off","off");
    const answered=(status,key,edits)=>newTask(key).then(async (x)=>{const id=x.rows[0].id;
      await db.query("select public.submit_intelligence_result($1,$2,$3,$4,$5)",[u1,id,status,JSON.stringify({status,summary:"s",edits}),key.padEnd(64,"0").replace(/[^0-9a-f]/g,"a").slice(0,64)]);return id;});
    const proposal=await answered("proposal_received","aa1",[{path:"next.config.ts",baseHash:"1".repeat(64),content:"x"}]);
    const human=await answered("needs_human","bb1",[]);
    const ask=(task,user=u1,finding=task,key="ai-fix-1")=>db.query("select public.request_repair_action($1,$2,'ai-fix-pr',$3,null,$4,null,$5) as id",[user,r1,finding,key,task]).then((x)=>x.rows[0].id);
    const receipt=await ask(proposal);
    assert.equal(await ask(proposal),receipt);
    await assert.rejects(ask(human,u1,human,"ai-fix-2"),/proposal unavailable/);
    await assert.rejects(ask(proposal,u1,"other-finding","ai-fix-3"));
    await assert.rejects(db.query("select public.request_repair_action($1,$2,'ai-fix-pr',$3,null,'ai-fix-4',null,null)",[u1,r1,proposal]));
    await assert.rejects(db.query("select public.request_repair_action($1,$2,'risk-fix-pr','f',null,'ai-fix-5',null,$3)",[u1,r1,proposal]));
    await db.exec("reset role");
    assert.deepEqual((await db.query("select action,task_id,finding_id from public.repair_action_receipts where id=$1",[receipt])).rows,[{action:"ai-fix-pr",task_id:proposal,finding_id:proposal}]);
    await db.query("update public.repair_action_receipts set status='failed',failure_code='source_changed' where id=$1",[receipt]);
    await db.exec("set role service_role");
  });
  // 3G-1: one ShipLock-funded model run per account, bound to a leased audit run.
  await check("the first-scan credit funds exactly one audit run per account and per GitHub installation", async () => {
    await db.exec("reset role");
    const leased=async(user,repo)=>{
      const run=(await db.query("insert into public.audit_runs(user_id,repository_id,full_name,status) values ($1,$2,'acme/app','running') returning id",[user,repo])).rows[0].id;
      const token="99999999-9999-4999-8999-"+Math.random().toString(16).slice(2,14).padEnd(12,"0");
      const job=(await db.query("insert into public.execution_jobs(user_id,repository_id,audit_run_id,kind,deduplication_key,status,lease_token,lease_until,attempts) values ($1,$2,$3,'audit',$4,'running',$5,now()+interval '5 minutes',1) returning id",[user,repo,run,"credit:"+run,token])).rows[0].id;
      return {run,job,token};
    };
    const a=await leased(u1,r1), b=await leased(u1,r1);
    await db.exec("set role service_role");
    const claim=(x,user=u1)=>db.query("select public.claim_first_scan_credit($1,$2,$3,$4) as ok",[user,x.run,x.job,x.token]).then((q)=>q.rows[0].ok);
    assert.equal(await claim({...a,token:"00000000-0000-4000-8000-000000000000"}),false); // wrong lease
    assert.equal(await claim(a),true);
    assert.equal(await claim(a),true);   // a retry of the same run reuses the credit
    assert.equal(await claim(b),false);  // any later run is not ShipLock-funded
    // Another account on the same GitHub installation (account recreation) gets no second credit.
    await db.exec("reset role");
    await db.query("update public.user_profiles set github_installation_id=42 where id=$1",[u2]);
    const c=await leased(u2,r2);
    await db.exec("set role service_role");
    assert.equal(await claim(c,u2),false);
    // The credit is a ledger: deleting the run it funded does not erase it.
    await db.exec("reset role");
    await db.query("delete from public.execution_jobs where audit_run_id=$1",[a.run]);
    await db.query("delete from public.audit_runs where id=$1",[a.run]);
    assert.equal((await db.query("select count(*)::int as n from public.first_scan_credits where github_installation_id=42")).rows[0].n,1);
    await db.exec("set role service_role");
  });
  // 3H-1: a hard daily cap on manual audits per account; scheduled work is unaffected.
  await check("manual audits are capped at 20 per account per rolling day, replays and scheduled runs excepted", async () => {
    await db.exec("reset role");
    await db.query("delete from public.execution_jobs where user_id=$1 and kind='audit'",[u2]);
    // Earlier checks left manual-default runs for u2; top up to exactly 19 in the window.
    const existing=(await db.query("select count(*)::int as n from public.audit_runs where user_id=$1 and trigger='manual' and started_at>now()-interval '24 hours'",[u2])).rows[0].n;
    assert.ok(existing<=19);
    await db.query("insert into public.audit_runs(user_id,repository_id,full_name,status,trigger,started_at) select $1,$2,'acme/two','complete','manual',now()-interval '1 hour' from generate_series(1,$3::int)",[u2,r2,19-existing]);
    await db.query("insert into public.audit_runs(user_id,repository_id,full_name,status,trigger,started_at) values ($1,$2,'acme/two','complete','manual',now()-interval '25 hours')",[u2,r2]);
    await db.exec("set role service_role");
    const manual=(key,trigger="manual")=>db.query("select * from public.enqueue_repository_audit($1,$2,$3,$4)",[u2,r2,key,trigger]).then((x)=>x.rows[0]);
    const twentieth=await manual("quota-20");
    assert.ok(twentieth.run_id);
    assert.deepEqual(await manual("quota-20"),twentieth);                   // idempotent replay is not a new run
    await assert.rejects(manual("quota-21"),/audit quota reached/);         // the 21st in 24h is refused
    assert.ok((await manual("quota-sched","scheduled")).run_id);           // scheduled work is not a manual click
  });
  // 3H-2: provisional caps on the other customer-click paths.
  await check("manual provider rechecks are capped at 20 per account per rolling day, replays excepted", async () => {
    await db.exec("reset role");
    const existing=(await db.query("select count(*)::int as n from public.monitoring_job_context where user_id=$1 and trigger_source='manual' and created_at>now()-interval '24 hours'",[legacy])).rows[0].n;
    await db.exec("set role service_role");
    const recheck=(key)=>db.query("select public.enqueue_monitoring_job($1,'manual',$2) as id",[legacy,key]).then((x)=>x.rows[0].id);
    let last;
    for (let i=existing;i<20;i++) last=await recheck(`quota-recheck-${i}`);
    await assert.rejects(recheck("quota-recheck-over"),/recheck quota reached/);
    assert.equal(await recheck(`quota-recheck-19`),last);
    assert.ok(await db.query("select public.enqueue_monitoring_job($1,'deploy','quota-deploy') as id",[legacy]).then((x)=>x.rows[0].id));
  });
  await check("repair clicks are capped at 30 per account per rolling day, replays excepted", async () => {
    await db.exec("reset role");
    const existing=(await db.query("select count(*)::int as n from public.repair_action_receipts where user_id=$1 and requested_at>now()-interval '24 hours'",[u1])).rows[0].n;
    await db.query("delete from public.execution_jobs where user_id=$1 and status='queued' and kind<>'repair'",[u1]);
    await db.exec("set role service_role");
    const click=(key)=>db.query("select public.request_repair_action($1,$2,'dependency-bump-pr',null,null,$3) as id",[u1,r1,key]).then((x)=>x.rows[0].id);
    let last;
    for (let i=existing;i<30;i++) last=await click(`quota-repair-${i}`);
    await assert.rejects(click("quota-repair-over"),/repair quota reached/);
    assert.equal(await click(`quota-repair-29`),last);
  });
  await check("an account holds at most 10 active access tokens; revoked ones do not count", async () => {
    await db.exec("reset role");
    const token=(n)=>db.query("insert into public.api_tokens(user_id,token_hash) values ($1,$2)",[u2,`quota-token-${n}`]);
    for (let i=0;i<10;i++) await token(i);
    await assert.rejects(token(10),/token limit reached/);
    await db.query("update public.api_tokens set revoked_at=now() where token_hash='quota-token-0'");
    await token(11);
    await db.exec("set role service_role");
  });
  // 3H-3: pin the queue's per-tenant fairness (characterization; migration 056).
  await check("a claim skips a tenant that already has a running job, so one busy tenant cannot starve others", async () => {
    await db.exec("reset role");
    const fa="aaaaaaaa-0000-4000-8000-00000000fa01", fb="aaaaaaaa-0000-4000-8000-00000000fb02";
    await db.query("insert into auth.users values ($1),($2) on conflict do nothing",[fa,fb]);
    await db.query("insert into public.user_profiles(id) values ($1),($2) on conflict do nothing",[fa,fb]);
    // Earlier checks leave running jobs behind; the global cap (8 running) would
    // otherwise mask the per-tenant rule this check pins.
    await db.query("update public.execution_jobs set status='dead',lease_token=null,lease_until=null where status='running' or (kind='notification' and status='queued')");
    // Tenant A: three old queued jobs plus one running. Tenant B: one newer queued job.
    for (const n of [1,2,3]) await db.query("insert into public.execution_jobs(user_id,kind,deduplication_key,run_after,created_at) values ($1,'notification',$2,now()-make_interval(mins=>$3),now()-make_interval(mins=>$3))",[fa,`fair-a-${n}`,60-n]);
    await db.query("insert into public.execution_jobs(user_id,kind,deduplication_key,status,lease_token,lease_until,attempts) values ($1,'notification','fair-a-running','running','bbbbbbbb-0000-4000-8000-000000000001',now()+interval '5 minutes',1)",[fa]);
    await db.query("insert into public.execution_jobs(user_id,kind,deduplication_key,run_after,created_at) values ($1,'notification','fair-b-1',now()-interval '1 minute',now()-interval '1 minute')",[fb]);
    await db.exec("set role service_role");
    const claimed=(await db.query("select user_id,deduplication_key from public.claim_execution_job('notification',60)")).rows;
    assert.deepEqual(claimed,[{user_id:fb,deduplication_key:"fair-b-1"}]);
    // With both tenants now busy, nothing else is claimed for this kind.
    assert.deepEqual((await db.query("select id from public.claim_execution_job('notification',60)")).rows,[]);
    await db.exec("reset role");
    await db.query("update public.execution_jobs set status='dead',lease_token=null,lease_until=null where user_id in ($1,$2)",[fa,fb]);
    await db.exec("set role service_role");
  });
  // 8-R: a merged ShipLock PR is stamped on its receipt exactly once.
  await check("a merge stamps only the owner's opened receipt for that repository and PR, once", async () => {
    await db.exec("reset role");
    const receipt=(await db.query("select id from public.repair_action_receipts where user_id=$1 and repository_id=$2 limit 1",[u1,r1])).rows[0].id;
    await db.query("update public.repair_action_receipts set status='opened',pr_url='https://github.com/acme/one/pull/77',pr_number=77,failure_code=null,merged_at=null where id=$1",[receipt]);
    await db.exec("set role service_role");
    const merge=(user,repo,pr)=>db.query("select public.record_repair_merge($1,$2,$3) as n",[user,repo,pr]).then((x)=>x.rows[0].n);
    assert.equal(await merge(u2,r1,77),0);   // another tenant
    assert.equal(await merge(u1,r1,78),0);   // another PR
    assert.equal(await merge(u1,r1,77),1);
    assert.equal(await merge(u1,r1,77),0);   // a redelivery does not restamp
    await db.exec("reset role");
    assert.ok((await db.query("select merged_at from public.repair_action_receipts where id=$1",[receipt])).rows[0].merged_at);
    await db.exec("set role service_role");
  });
  // 2F-2a: traffic is bound to a repository through an explicit site.
  await check("a traffic site binds one normalized host to the owner's selected repository, with its own token", async () => {
    await db.exec("reset role");
    await db.query("update public.repositories set selected=true where id in ($1,$2)",[r1,r3]);   // earlier checks deselect
    await db.exec("set role service_role");
    const site=(user,repo,host)=>db.query("select * from public.create_traffic_site($1,$2,$3)",[user,repo,host]).then((x)=>x.rows[0]);
    const a=await site(u1,r1,"App.Example.com");
    assert.match(a.ingest_token,/^[0-9a-f-]{36}$/);
    await db.exec("reset role");
    assert.deepEqual((await db.query("select host,repository_id,source from public.traffic_sites where id=$1",[a.site_id])).rows,[{host:"app.example.com",repository_id:r1,source:"snippet"}]);
    await db.exec("set role service_role");
    assert.deepEqual(await site(u1,r1,"app.example.com"),a);                 // same host, same repo: idempotent
    await assert.rejects(site(u1,r3,"app.example.com"),/host already bound/); // one repository per host
    await assert.rejects(site(u1,r2,"other.example.com"));                   // another tenant's repository
    await assert.rejects(site(u1,r1,"https://bad host/"));                   // not a hostname
    await assert.rejects(site(u1,r1,"localhost"));                           // not a public host
    assert.equal((await db.query("select public.revoke_traffic_site($1,$2) as ok",[u2,a.site_id])).rows[0].ok,false);
    assert.equal((await db.query("select public.revoke_traffic_site($1,$2) as ok",[u1,a.site_id])).rows[0].ok,true);
    const b=await site(u1,r3,"app.example.com");                              // a revoked host can be rebound
    assert.notEqual(b.ingest_token,a.ingest_token);
    await db.exec("reset role");
    await db.query("insert into public.traffic_events(user_id,source_id,path,method,site_id,repository_id) values ($1,'s','/x','GET',$2,$3)",[u1,b.site_id,r3]);
    await db.exec("set role service_role");
  });
  // 2F-4: provider-log traffic observations, replaced per run, bounded, no IPs.
  await check("traffic observations are replaced per repository and source, bounded, and refuse a foreign repository", async () => {
    const replace=(user,repo,paths)=>db.query("select public.replace_traffic_observations($1,$2,'supabase',$3) as n",[user,repo,JSON.stringify(paths)]).then((x)=>x.rows[0].n);
    assert.equal(await replace(u1,r1,[{path:"/auth/v1/token",suspiciousRequests:25},{path:"/rest/v1/orders",suspiciousRequests:3}]),2);
    assert.equal(await replace(u1,r1,[{path:"/rest/v1/orders",suspiciousRequests:7}]),1);
    await db.exec("reset role");
    assert.deepEqual((await db.query("select path,suspicious_requests from public.traffic_route_observations where user_id=$1 and repository_id=$2",[u1,r1])).rows,[{path:"/rest/v1/orders",suspicious_requests:7}]);
    await db.exec("set role service_role");
    await assert.rejects(replace(u1,r2,[{path:"/x",suspiciousRequests:1}]));
    await assert.rejects(replace(u1,r1,Array.from({length:21},(_,i)=>({path:`/p${i}`,suspiciousRequests:1}))));
    await assert.rejects(replace(u1,r1,[{path:"",suspiciousRequests:1}]));
    assert.equal(await replace(u1,r1,[]),0);
  });
  await check("client roles cannot touch intelligence tasks", async () => {
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.traffic_route_observations"));
    await assert.rejects(db.query("select * from public.traffic_sites"));
    await assert.rejects(db.query("select * from public.create_traffic_site($1,$2,'x.example.com')",[u1,r1]));
    await assert.rejects(db.query("select public.record_repair_merge($1,$1,1)",[u1]));
    await assert.rejects(db.query("select * from public.first_scan_credits"));
    await assert.rejects(db.query("select public.claim_first_scan_credit($1,$1,$1,$1)",[u1]));
    await assert.rejects(db.query("select * from public.intelligence_credentials"));
    await assert.rejects(db.query("select public.claim_api_intelligence_task($1,$1)",[u1]));
    await db.exec("reset role; set role service_role");
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.intelligence_scan_jobs"));
    await assert.rejects(db.query("select public.intelligence_month_usage($1)",[u1]));
    await assert.rejects(db.query("select public.enqueue_due_intelligence_scans(now(),10)"));
    await assert.rejects(db.query("select public.enqueue_pull_request_intelligence($1,$2,1,$3)",[u1,r1,head]));
    await db.exec("reset role; set role service_role");
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.intelligence_connections"));
    await assert.rejects(approve());
    await db.exec("reset role; set role service_role");
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select public.purge_intelligence_tasks()"));
    await db.exec("reset role; set role service_role");
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select * from public.intelligence_tasks"));
    await assert.rejects(newTask("intel-client"));
    await assert.rejects(db.query("select public.submit_intelligence_result($1,$1,'unavailable','{}'::jsonb,$2)",[u1,"9".repeat(64)]));
    await db.exec("reset role; set role service_role");
  });
  // 5A-2: every provider pass leaves one append-only snapshot of what it read.
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/087_provider_snapshots.sql", import.meta.url), "utf8"));
  await db.exec("grant select on public.provider_snapshots to service_role; set role service_role");
  const mEpoch = "c".repeat(64);
  await db.exec("reset role");
  await db.query("update public.user_profiles set supabase_mgmt_token_encrypted='m-cipher-2',supabase_mgmt_connection_epoch=$2 where id=$1",[legacy,mEpoch]);
  await db.exec("set role service_role");
  const persistSnapshot = (job, transport, identity, findings, retire, unread, snapshot) => db.query(
    "select public.persist_provider_monitor_result($1,$2,$3,$4,$5,null,$6,$7,$8,$9) as created",
    [legacy, job.id, job.token, transport, identity, JSON.stringify(findings), retire, JSON.stringify(unread), JSON.stringify(snapshot)]);
  const snapshots = async (transport) => (await db.query(
    "select job_id, scope, completeness, unread, reason, finding_count from public.provider_snapshots where user_id=$1 and transport=$2 order by id",
    [legacy, transport])).rows;
  await check("a provider commit appends one snapshot in the same transaction", async () => {
    const job = await monitorJob("5a2-snapshot");
    await persistSnapshot(job,"postgres-direct",pEpoch,[providerFinding("policy:s1")],true,["grants:"],{scope:"db.example.com",failed:["grants:"]});
    await persistSnapshot(job,"postgres-direct",pEpoch,[providerFinding("policy:s1")],true,[],{scope:"db.example.com",failed:[]});
    assert.deepEqual(await snapshots("postgres-direct"),[
      {job_id:job.id,scope:"db.example.com",completeness:"partial",unread:["grants:"],reason:null,finding_count:1},
      {job_id:job.id,scope:"db.example.com",completeness:"complete",unread:[],reason:null,finding_count:1},
    ]);
    // A fenced-out commit leaves no snapshot either.
    await assert.rejects(persistSnapshot(job,"postgres-direct","b".repeat(64),[],true,[],{scope:"db.example.com",failed:[]}));
    assert.equal((await snapshots("postgres-direct")).length,2);
  });
  await check("direct Postgres and Supabase findings never retire each other", async () => {
    const job = await monitorJob("5a2-sources");
    await persistSnapshot(job,"supabase-management",mEpoch,[providerFinding("policy:shared"),providerFinding("auth_policy:mfa_unavailable")],true,[],{scope:"proj",failed:[]});
    await persistSnapshot(job,"postgres-direct",pEpoch,[providerFinding("policy:shared")],true,[],{scope:"db.example.com",failed:[]});
    await persistSnapshot(job,"postgres-direct",pEpoch,[],true,[],{scope:"db.example.com",failed:[]});
    assert.deepEqual(await activeProvider("postgres-direct"),[]);
    assert.deepEqual(await activeProvider("policy"),["auth_policy:mfa_unavailable","policy:shared"]);
  });
  await check("a failed provider read is recorded only under the live lease", async () => {
    const job = await monitorJob("5a2-failed");
    await db.query("select public.record_provider_read_failure($1,$2,$3,'vercel','team_1','auth_failed')",[legacy,job.id,job.token]);
    assert.deepEqual((await snapshots("vercel")).map((r)=>[r.completeness,r.reason,r.scope]),[["failed","auth_failed","team_1"]]);
    await assert.rejects(db.query("select public.record_provider_read_failure($1,$2,$3,'vercel',null,'auth_failed')",[legacy,job.id,u2]));
    await assert.rejects(db.query("select public.record_provider_read_failure($1,$2,$3,'vercel',null,'Not A Code')",[legacy,job.id,job.token]));
    await assert.rejects(db.query("select public.record_provider_read_failure($1,$2,$3,'github',null,'auth_failed')",[legacy,job.id,job.token]));
  });
  await check("snapshot payloads are bounded and typed", async () => {
    const job = await monitorJob("5a2-shape");
    await assert.rejects(persistSnapshot(job,"postgres-direct",pEpoch,[],false,[],{scope:"x".repeat(257),failed:[]}));
    await assert.rejects(persistSnapshot(job,"postgres-direct",pEpoch,[],false,[],{scope:"db",failed:"grants:"}));
    await assert.rejects(persistSnapshot(job,"postgres-direct",pEpoch,[],false,[],{scope:"db",failed:[7]}));
    await assert.rejects(persistSnapshot(job,"postgres-direct",pEpoch,[],false,[],null));
  });
  await check("pruning keeps 30 days and the latest snapshot per transport", async () => {
    await db.exec("reset role");
    await db.query("update public.provider_snapshots set observed_at=now()-interval '40 days' where user_id=$1",[legacy]);
    await db.exec("set role service_role");
    const pruned=(await db.query("select public.prune_provider_snapshots() as n")).rows[0].n;
    assert.equal(pruned,3);
    assert.deepEqual((await db.query("select transport from public.provider_snapshots where user_id=$1 order by transport",[legacy])).rows.map((r)=>r.transport),
      ["postgres-direct","supabase-management","vercel"]);
  });
  // Q8 / 2F-5b: the Supabase gateway traffic read leaves a snapshot too.
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/088_edge_traffic_snapshots.sql", import.meta.url), "utf8"));
  await db.exec("set role service_role");
  await check("a gateway traffic read is recorded under the live monitor lease", async () => {
    const job = await monitorJob("q8-edge");
    await db.query("select public.record_edge_traffic_snapshot($1,$2,$3,'proj',true)",[legacy,job.id,job.token]);
    await db.query("select public.record_edge_traffic_snapshot($1,$2,$3,'proj',false)",[legacy,job.id,job.token]);
    assert.deepEqual((await snapshots("supabase-edge-logs")).map((r)=>[r.scope,r.completeness,r.reason]),
      [["proj","complete",null],["proj","failed","log_unread"]]);
    await assert.rejects(db.query("select public.record_edge_traffic_snapshot($1,$2,$3,'proj',true)",[legacy,job.id,u2]));
    await assert.rejects(db.query("select public.record_edge_traffic_snapshot($1,$2,$3,$4,true)",[legacy,job.id,job.token,"x".repeat(257)]));
    // The other transports still work after the check was widened.
    await db.query("select public.record_provider_read_failure($1,$2,$3,'vercel',null,'timeout')",[legacy,job.id,job.token]);
  });
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/089_job_claim_kind_index.sql", import.meta.url), "utf8"));
  await check("job claims have a kind-first ready index (089)", async () => {
    const def=(await db.query("select indexdef from pg_indexes where indexname='execution_jobs_ready_kind'")).rows[0]?.indexdef ?? "";
    assert.match(def,/\(kind, run_after, created_at, id\) WHERE \(status = 'queued'::text\)/);
  });
  await db.exec("set role service_role");
  // Q5 / 6A-1: one receipt per proof the customer authorized, for one table.
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/090_proof_authorizations.sql", import.meta.url), "utf8"));
  await db.query("update public.repositories set selected=true where id=$1 and user_id=$2",[r1,u1]);
  await db.exec("set role service_role");
  const authorize = (user, repo, finding, table, key) => db.query(
    "select public.authorize_proof($1,$2,$3,$4,$5) as id",[user,repo,finding,table,key]);
  await check("a proof authorization is idempotent per key and bound to its payload", async () => {
    const id=(await authorize(u1,r1,"rls:orders","public.orders","p-1")).rows[0].id;
    assert.equal((await authorize(u1,r1,"rls:orders","public.orders","p-1")).rows[0].id,id);
    await assert.rejects(authorize(u1,r1,"rls:orders","public.invoices","p-1"));
    const row=(await db.query("select status, target_kind, statement_budget, extract(epoch from expires_at-created_at)::int as ttl from public.proof_authorizations where id=$1",[id])).rows[0];
    assert.deepEqual([row.status,row.target_kind,row.statement_budget],["issued","replica",60]);
    assert.equal(row.ttl,3600);
  });
  await check("a proof authorization refuses a foreign or deselected repository and a bad table", async () => {
    await assert.rejects(authorize(u2,r1,"rls:orders","public.orders","p-foreign"));
    await assert.rejects(authorize(u1,r1,"rls:orders","orders","p-noschema"));
    await assert.rejects(authorize(u1,r1,"rls:orders","public.Orders;drop","p-inject"));
    await assert.rejects(authorize(u1,r1,"","public.orders","p-empty"));
    await db.exec("reset role");
    await db.query("update public.repositories set selected=false where id=$1",[r1]);
    await db.exec("set role service_role");
    await assert.rejects(authorize(u1,r1,"rls:orders","public.orders","p-deselected"));
    await db.exec("reset role");
    await db.query("update public.repositories set selected=true where id=$1",[r1]);
    await db.exec("set role service_role");
  });
  await check("at most five authorizations are outstanding per account", async () => {
    for (let i=2;i<=5;i++) await authorize(u1,r1,"rls:orders",`public.t${i}`,`p-${i}`);
    await assert.rejects(authorize(u1,r1,"rls:orders","public.t6","p-6"));
  });
  await check("an authorization is consumed once, and never when expired, revoked or foreign", async () => {
    const id=(await authorize(u1,r1,"rls:orders","public.orders","p-1")).rows[0].id;
    const consume=(user,auth)=>db.query("select public.consume_proof_authorization($1,$2) as ok",[user,auth]);
    await assert.rejects(consume(u2,id));
    assert.equal((await consume(u1,id)).rows[0].ok,true);
    await assert.rejects(consume(u1,id));
    const other=(await db.query("select id from public.proof_authorizations where user_id=$1 and status='issued' order by created_at limit 2",[u1])).rows;
    assert.equal((await db.query("select public.revoke_proof_authorization($1,$2) as ok",[u1,other[0].id])).rows[0].ok,true);
    assert.equal((await db.query("select public.revoke_proof_authorization($1,$2) as ok",[u2,other[1].id])).rows[0].ok,false);
    await assert.rejects(consume(u1,other[0].id));
    await db.exec("reset role");
    await db.query("update public.proof_authorizations set created_at=now()-interval '2 hours', expires_at=now()-interval '1 hour' where id=$1",[other[1].id]);
    await db.exec("set role service_role");
    await assert.rejects(consume(u1,other[1].id));
    // An expired authorization no longer counts toward the outstanding limit.
    await authorize(u1,r1,"rls:orders","public.t7","p-7");
  });
  // Q6 / 6A-2: a proof job consumes its authorization and records one run.
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/091_proof_jobs.sql", import.meta.url), "utf8"));
  await db.exec("set role service_role");
  const proofAuth = async (key, table="public.orders") => (await authorize(u1,r1,"policy:public.orders:read",table,key)).rows[0].id;
  const proofClaim = async (jobId) => {
    await db.exec("reset role");
    const token=(await db.query("update public.execution_jobs set status='running',lease_token=gen_random_uuid(),lease_until=now()+interval '5 minutes',attempts=1 where id=$1 returning lease_token",[jobId])).rows[0].lease_token;
    await db.exec("set role service_role");
    return token;
  };
  await check("a proof job consumes its authorization once, atomically", async () => {
    await db.exec("reset role");
    await db.query("update public.proof_authorizations set status='revoked' where user_id=$1 and status='issued'",[u1]);
    await db.exec("set role service_role");
    const auth=await proofAuth("q6-1");
    const job=(await db.query("select public.enqueue_proof_job($1,$2) as id",[u1,auth])).rows[0].id;
    const row=(await db.query("select kind, repository_id, deduplication_key from public.execution_jobs where id=$1",[job])).rows[0];
    assert.deepEqual(row,{kind:"proof",repository_id:r1,deduplication_key:`proof:${auth}`});
    assert.equal((await db.query("select status from public.proof_authorizations where id=$1",[auth])).rows[0].status,"consumed");
    await assert.rejects(db.query("select public.enqueue_proof_job($1,$2)",[u1,auth]));
    await assert.rejects(db.query("select public.enqueue_proof_job($1,$2)",[u2,await proofAuth("q6-2")]));
    // A refused enqueue leaves the other account's authorization unconsumed.
    assert.equal((await db.query("select count(*)::int n from public.proof_authorizations where idempotency_key='q6-2' and status='issued'")).rows[0].n,1);
  });
  await check("a proof run is recorded once, only under the live proof lease", async () => {
    const auth=await proofAuth("q6-3");
    const job=(await db.query("select public.enqueue_proof_job($1,$2) as id",[u1,auth])).rows[0].id;
    const token=await proofClaim(job);
    const record=(t,outcome,reason,n)=>db.query("select public.record_proof_run($1,$2,$3,$4,$5,$6)",[u1,job,t,outcome,reason,n]);
    await assert.rejects(record(u2,"ran",null,4));
    await assert.rejects(record(token,"proven",null,4));
    await assert.rejects(record(token,"could_not_test",null,0));
    await assert.rejects(record(token,"ran",null,201));
    await record(token,"reproduced",null,7);
    await assert.rejects(record(token,"ran",null,4));
    const run=(await db.query("select authorization_id, finding_id, table_name, outcome, statements_run from public.proof_runs where job_id=$1",[job])).rows;
    assert.deepEqual(run,[{authorization_id:auth,finding_id:"policy:public.orders:read",table_name:"public.orders",outcome:"reproduced",statements_run:7}]);
  });
  // Q10 / 12B: one usage receipt per model call, for cost per run.
  await db.exec("reset role");
  await db.exec(await readFile(new URL("../supabase/migrations/092_model_usage_receipts.sql", import.meta.url), "utf8"));
  await db.exec("grant select, insert on public.model_usage_receipts to service_role; set role service_role");
  const usage = (over) => db.query(`insert into public.model_usage_receipts(user_id,purpose,funded_by,model,input_tokens,output_tokens,stop_reason,audit_run_id,intelligence_task_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [over.user ?? u1, over.purpose, over.funded, over.model ?? "claude-haiku-4-5", over.input ?? 10, over.output ?? 5,
    over.stop ?? "end_turn", over.run ?? null, over.task ?? null]);
  await check("model usage receipts bind purpose, payer and run", async () => {
    const run = "77777777-7777-4777-8777-777777777777";
    await usage({purpose:"first_scan",funded:"shiplock",run});
    await usage({purpose:"customer_api",funded:"customer",task:run});
    await usage({purpose:"narrative",funded:"shiplock"});
    await assert.rejects(usage({purpose:"first_scan",funded:"customer",run}));
    await assert.rejects(usage({purpose:"customer_api",funded:"shiplock",task:run}));
    await assert.rejects(usage({purpose:"first_scan",funded:"shiplock"}));
    await assert.rejects(usage({purpose:"customer_api",funded:"customer"}));
    await assert.rejects(usage({purpose:"narrative",funded:"shiplock",run}));
    await assert.rejects(usage({purpose:"first_scan",funded:"shiplock",run,input:-1}));
    await assert.rejects(usage({purpose:"bogus",funded:"shiplock"}));
    await assert.rejects(usage({purpose:"narrative",funded:"shiplock",model:""}));
    assert.equal((await db.query("select count(*)::int n from public.model_usage_receipts")).rows[0].n,3);
  });
  await check("client roles cannot commit provider results or read snapshots", async () => {
    await db.exec("reset role; set role authenticated");
    await assert.rejects(db.query("select public.persist_provider_monitor_result($1,$1,$1,'postgres-direct','x',null,'[]'::jsonb,false,'[]'::jsonb,'{}'::jsonb)",[legacy]));
    await assert.rejects(db.query("select * from public.provider_snapshots"));
    await assert.rejects(db.query("select public.record_provider_read_failure($1,$1,$1,'vercel',null,'auth_failed')",[legacy]));
    await assert.rejects(db.query("select public.prune_provider_snapshots()"));
    await assert.rejects(db.query("select public.record_edge_traffic_snapshot($1,$1,$1,'proj',true)",[legacy]));
    await assert.rejects(db.query("select * from public.proof_authorizations"));
    await assert.rejects(db.query("select public.authorize_proof($1,$2,'rls:x','public.x','k')",[u1,r1]));
    await assert.rejects(db.query("select public.consume_proof_authorization($1,$1)",[u1]));
    await assert.rejects(db.query("select public.revoke_proof_authorization($1,$1)",[u1]));
    await assert.rejects(db.query("select * from public.proof_runs"));
    await assert.rejects(db.query("select * from public.model_usage_receipts"));
    await assert.rejects(db.query("select public.enqueue_proof_job($1,$1)",[u1]));
    await assert.rejects(db.query("select public.record_proof_run($1,$1,$1,'ran',null,1)",[u1]));
    await db.exec("reset role");
  });
  console.log(`${checks} SQL checks passed. Single-connection PostgreSQL WASM; multi-session contention and hosted Supabase remain unverified.`);
} finally { await db.close(); }

import { beforeEach,expect,it,vi } from "vitest";
import { z } from "zod";
const state=vi.hoisted(()=>({
  reads:{user_profiles:vi.fn(),repositories:vi.fn()},filters:vi.fn(),rpc:vi.fn(),token:vi.fn(),repos:vi.fn(),collect:vi.fn(),claim:vi.fn(),enqueue:vi.fn(),execute:vi.fn(),
}));
vi.mock("@/lib/supabase",()=>({getSupabaseAdmin:()=>({from:(table:keyof typeof state.reads)=>{
  const query={eq:(key:string,value:unknown)=>{state.filters(table,key,value);return query;},maybeSingle:()=>state.reads[table]()};
  return {select:()=>query};
},rpc:state.rpc})}));
vi.mock("@/lib/deep/github",()=>({getInstallationToken:state.token,listRepos:state.repos}));
vi.mock("@/lib/deep/githubRun",()=>({collectRepositorySource:state.collect}));
vi.mock("./queue",()=>{class PermanentJobError extends Error{} return {PermanentJobError,claimJob:state.claim,enqueueJob:state.enqueue,executeClaimedJob:state.execute,withLeaseHeartbeat:(_job:unknown,work:()=>Promise<unknown>)=>work(),JobKind:z.enum(["audit","source","monitor","dependency","graph","pr-check"])};});
import {enqueueFollowUpsAfterSource,executeSourceJob,runNextSourceJob} from "./sourceWorker";
import {PermanentJobError,type ClaimedJob} from "./queue";
const job:ClaimedJob={id:"11111111-1111-4111-8111-111111111111",user_id:"22222222-2222-4222-8222-222222222222",repository_id:"33333333-3333-4333-8333-333333333333",audit_run_id:null,deduplication_key:"manual-source:test",kind:"source",status:"running",attempts:1,lease_token:"55555555-5555-4555-8555-555555555555",lease_until:"2099-01-01T00:00:00Z",checkpoint:0};

beforeEach(()=>{
  vi.clearAllMocks();
  state.reads.user_profiles.mockResolvedValue({data:{github_installation_id:42},error:null});
  state.reads.repositories.mockResolvedValue({data:{full_name:"acme/app",github_repo_id:"9",default_branch:"main",selected:true},error:null});
  state.token.mockResolvedValue("token");
  state.repos.mockResolvedValue([{id:"9",fullName:"acme/app",defaultBranch:"main",isPrivate:true,visibility:"private"}]);
  state.collect.mockResolvedValue({snapshot:{repositoryId:job.repository_id,providerRepositoryId:"9",repositoryFullName:"acme/app",installationId:"42",ref:"main",recordedAt:"2026-09-22T00:00:00Z",completeness:"partial",filesAttempted:1,filesRead:1,routes:[],liveFiles:[],hasEntryPoints:false,dependencies:[]},findings:[{id:"acme/app::github:secret:key:file",severity:"CRITICAL",title:"Secret",consequence:"Rotate",packageName:null,version:null,vulnId:null,cveId:null}]});
  state.rpc.mockResolvedValue({data:{total:1,newCount:1,resolvedCount:0},error:null});
  state.enqueue.mockResolvedValue("66666666-6666-4666-8666-666666666666");
});

it("collects one exact current repository and persists through the live lease",async()=>{
  await executeSourceJob(job);
  expect(state.collect).toHaveBeenCalledWith("token",expect.objectContaining({fullName:"acme/app"}),job.repository_id,42);
  expect(state.rpc).toHaveBeenCalledWith("persist_repository_source",expect.objectContaining({p_job:job.id,p_token:job.lease_token,p_repository:job.repository_id,p_findings:[expect.objectContaining({finding_id:"acme/app::github:secret:key:file"})]}));
});

it("permanently refuses a changed branch or deselected repository",async()=>{
  state.repos.mockResolvedValue([{fullName:"acme/app",defaultBranch:"develop"}]);
  await expect(executeSourceJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.collect).not.toHaveBeenCalled();
});

it("refuses a provider repository id that was renamed or replaced",async()=>{
  state.repos.mockResolvedValue([{id:"10",fullName:"acme/app",defaultBranch:"main"}]);
  await expect(executeSourceJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.collect).not.toHaveBeenCalled();
});

it("retries provider and persistence failures",async()=>{
  state.rpc.mockResolvedValue({data:null,error:{message:"private"}});
  await expect(executeSourceJob(job)).rejects.toThrow("could not be saved");
});

it("chains repository-scoped dependency and graph jobs only after source persistence",async()=>{
  await enqueueFollowUpsAfterSource(job);
  expect(state.enqueue).toHaveBeenNthCalledWith(1,job.user_id,job.repository_id,"dependency",`dependency-after-source:${job.id}`);
  expect(state.enqueue).toHaveBeenNthCalledWith(2,job.user_id,job.repository_id,"graph",`graph-after-source:${job.id}`);
});

it("deduplicates a scheduled source follow-up with the daily dependency admission",async()=>{
  const scheduled={...job,deduplication_key:`scheduled-source:${job.repository_id}:2026-09-22`};
  await enqueueFollowUpsAfterSource(scheduled);
  expect(state.enqueue).toHaveBeenNthCalledWith(1,job.user_id,job.repository_id,"dependency",`scheduled-dependency:${job.repository_id}:2026-09-22`);
});

it("claims at most one source job",async()=>{
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextSourceJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job);state.execute.mockResolvedValue(undefined);
  expect(await runNextSourceJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job,[executeSourceJob,enqueueFollowUpsAfterSource]);
});

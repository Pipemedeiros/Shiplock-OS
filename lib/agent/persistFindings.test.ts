import { expect, it, vi } from "vitest";
import { persistFindings } from "./audit";
import type { AgentFinding } from "./findings";

const finding: AgentFinding = { id:"f",title:"Finding",consequence:"c",severity:"CRITICAL",confidence:"inferred",
  attackClass:"missing_authorization",entry:"/api/x",file:"app/api/x/route.ts",blastRadius:null,fixKind:"pr",claims:[] };
// Transaction, crash, idempotence, source/tenant isolation and partial-index
// behavior are exercised on actual PostgreSQL in test-foundation-sql.mjs.
it.each([true,false])("sends identity and preservation intent to the single transaction: %s", async (preserve) => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[finding],{rpc} as never,preserve);
  expect(rpc).toHaveBeenCalledExactlyOnceWith("persist_repository_findings",{
    p_user:"u",p_repository:"repo",p_run:"run",p_findings:[finding],p_preserve:preserve,
    p_job:null,p_token:null,
  });
});
it("carries the durable job fencing identity into the findings transaction", async () => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[finding],{rpc} as never,false,{jobId:"job",token:"token"});
  expect(rpc.mock.calls[0][1]).toMatchObject({p_job:"job",p_token:"token"});
});
it("sends empty partial observations without independently archiving", async () => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[],{rpc} as never,true);
  expect(rpc.mock.calls[0][1]).toMatchObject({p_findings:[],p_preserve:true});
});
it("throws a generic failure on a failed transaction", async () => {
  const rpc=vi.fn().mockResolvedValue({error:{message:"private backend detail"}});
  await expect(persistFindings("u","repo","run",[],{rpc} as never)).rejects.toThrow("Findings could not be saved");
  expect(rpc).toHaveBeenCalledOnce();
});
it("propagates a lost connection without retrying an uncertain transaction", async () => {
  const rpc=vi.fn().mockRejectedValue(new Error("connection lost"));
  await expect(persistFindings("u","repo","run",[finding],{rpc} as never)).rejects.toThrow("connection lost");
  expect(rpc).toHaveBeenCalledOnce();
});

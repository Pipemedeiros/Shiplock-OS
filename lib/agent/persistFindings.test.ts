import { expect, it, vi } from "vitest";
import { persistFindings, retirableClasses } from "./audit";
import type { AgentFinding } from "./findings";
import type { RouteFact } from "@/lib/graph/routeInventory";

const finding: AgentFinding = { id:"f",title:"Finding",consequence:"c",severity:"CRITICAL",confidence:"inferred",
  attackClass:"missing_authorization",entry:"/api/x",file:"app/api/x/route.ts",blastRadius:null,fixKind:"pr",claims:[] };
// Transaction, crash, idempotence, source/tenant isolation and partial-index
// behavior are exercised on actual PostgreSQL in test-foundation-sql.mjs.
it.each([[[]],[["committed_secret"]],[["committed_secret","permission_gap"]]] as const)(
  "sends identity and the classes this run may retire to the single transaction: %j", async (retire) => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[finding],{rpc} as never,[...retire]);
  expect(rpc).toHaveBeenCalledExactlyOnceWith("persist_audit_findings",{
    p_user:"u",p_repository:"repo",p_run:"run",p_findings:[finding],p_retire:[...retire],
    p_job:null,p_token:null,
  });
});
it("carries the durable job fencing identity into the findings transaction", async () => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[finding],{rpc} as never,[],{jobId:"job",token:"token"});
  expect(rpc.mock.calls[0][1]).toMatchObject({p_job:"job",p_token:"token"});
});
it("retires nothing by default", async () => {
  const rpc=vi.fn().mockResolvedValue({error:null});
  await persistFindings("u","repo","run",[],{rpc} as never);
  expect(rpc.mock.calls[0][1]).toMatchObject({p_findings:[],p_retire:[]});
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

// A deterministic finding may close only when this run re-checked everything
// that could have produced it; a finding from the customer's agent never
// closes because an audit, which does not reason, did not repeat it.
const readable = { identityReadable:true, ownershipReadable:true, dataReadable:true, machineGateReadable:true, serviceRoleReadable:true } as RouteFact;
it("retires committed credentials only after reading the whole archive", () => {
  expect(retirableClasses({ truncated:true, skipped:0, routes:[readable] })).toEqual([]);
  expect(retirableClasses({ truncated:false, skipped:3, routes:[readable] })).toEqual([]);
  expect(retirableClasses({ truncated:false, skipped:0, routes:[readable] })).toEqual(["committed_secret","permission_gap"]);
});
it("retires permission gaps only when every route's facts were readable", () => {
  expect(retirableClasses({ truncated:false, skipped:0, routes:[readable,{ ...readable, identityReadable:false }] }))
    .toEqual(["committed_secret"]);
  expect(retirableClasses({ truncated:false, skipped:0, routes:[{ ...readable, dataReadable:false }] })).toEqual(["committed_secret"]);
});

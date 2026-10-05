import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { StackReport } from "@/lib/agent/stack";

// Audit reasoning on the customer's own agent (migration 098). No model and no
// network: Supabase and GitHub are mocked.
const mocks = vi.hoisted(() => ({ rpc: vi.fn(), file: vi.fn(), read: vi.fn() }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: vi.fn(async () => "token"), getFile: mocks.file }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc, from: (table: string) => {
  const chain = { select: () => chain, eq: () => chain, maybeSingle: () => mocks.read(table) };
  return chain;
} }) }));

import { approvedAgent, offerAuditReasoning, reasoningContext, submitReasoningResult, submitVerificationResult, taskBrief,
  verificationBatches, type ReasoningContext, type ReasoningTask } from "./reasoning";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const user = "11111111-1111-4111-8111-111111111111", repo = "22222222-2222-4222-8222-222222222222";
const run = "33333333-3333-4333-8333-333333333333", taskId = "44444444-4444-4444-8444-444444444444";
const verifyId = "55555555-5555-4555-8555-555555555555", commit = "a".repeat(40);
const handler = "app/api/orders/route.ts";
const source = "export async function GET() {\n  return Response.json(await db.from(\"orders\").select(\"*\"));\n}\n";
const route = (over: Partial<RouteFact> = {}): RouteFact => ({ path: "/api/orders", file: handler, methods: ["GET"], tables: ["orders"],
  authenticated: false, machineGated: false, usesServiceRole: false, ownershipFiltered: false, identityReadable: true, identityGap: null,
  dataReadable: true, dataGap: null, ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true,
  machineGateGap: null, via: ["lib/db.ts"], ...over });
const next: StackReport = { tools: [{ id: "next", name: "Next.js", kind: "framework", evidence: "package.json", usedIn: [] }],
  authUnknown: false, databaseUnknown: false } as unknown as StackReport;
const context = (over: Partial<Parameters<typeof reasoningContext>[0]> = {}) => reasoningContext({
  routes: [route(), route({ path: "/api/health", file: "app/api/health/route.ts", tables: [] })], stack: next, tables: ["orders"],
  files: [handler, "lib/db.ts", "prisma/schema.prisma", "README.md"], liveFacts: [], possessionGates: new Map(),
  oneIdAccess: new Map(), hasDatabase: false, ...over });
const ctx = context()!;
const reasoningTask = (over: Partial<ReasoningTask> = {}): ReasoningTask => ({ id: taskId, user_id: user, repository_id: repo,
  commit_sha: commit, host: "claude-code", kind: "attack_reasoning", audit_run_id: run, parent_task_id: null, context: ctx,
  sources: [{ path: handler, sourceHash: hash(source) }], repositories: { full_name: "acme/app" }, ...over });
const identity = { taskId, tenantId: user, repositoryId: repo, commit };
const hypothesis = { entry: "/api/orders", attackClass: "missing_authentication", title: "Anyone can read every order",
  consequence: "An anonymous caller reads all orders.", citedFiles: [handler], citedTables: ["orders"] };
const answer = (hypotheses: unknown[]) => ({ version: 1, identity, host: "claude-code", model: "agent", usage: null, status: "proposed",
  hypotheses, truncated: false });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.read.mockImplementation(async (table: string) => table === "user_profiles"
    ? { data: { github_installation_id: 42 }, error: null }
    : table === "intelligence_connections" ? { data: { host: "claude-code", revoked_at: null, run_token_budget: 50000 }, error: null }
    : { data: { context: ctx }, error: null });
  mocks.rpc.mockImplementation(async (name: string) => ({ data: name === "create_verification_task" ? verifyId
    : name === "create_audit_reasoning_task" ? taskId : "accepted", error: null }));
  mocks.file.mockResolvedValue(source);
});

describe("reasoningContext", () => {
  it("holds the routes that reach data, the files a claim may cite, and the prompt the corpus measures", () => {
    expect(ctx.routes.map((r) => r.path)).toEqual(["/api/orders"]);
    expect(ctx.files.sort()).toEqual([handler, "lib/db.ts", "prisma/schema.prisma"].sort());
    expect(ctx.prompt).toContain("/api/orders id=anonymous scope=unscoped");
    expect(ctx.system).toContain("security engineer");
  });

  it("asks nothing of an inventory-only stack or of routes that reach no table", () => {
    expect(context({ stack: { tools: [], authUnknown: true, databaseUnknown: true } as unknown as StackReport })).toBeNull();
    expect(context({ routes: [route({ tables: [] })] })).toBeNull();
  });
});

describe("offerAuditReasoning", () => {
  const agent = { host: "claude-code" as const, runTokenBudget: 50000 };
  const offer = (approved: typeof agent | null = agent) => offerAuditReasoning({ userId: user, repositoryId: repo, runId: run, commit,
    fullName: "acme/app", context: ctx, contents: new Map([[handler, source]]), agent: approved });

  it("creates one reasoning task per audit for the approved host, hashing handlers from the audit's own archive", async () => {
    expect(await offer()).toBe(taskId);
    const [name, args] = mocks.rpc.mock.calls[0];
    expect(name).toBe("create_audit_reasoning_task");
    expect(args).toMatchObject({ p_user: user, p_repository: repo, p_run: run, p_commit: commit, p_host: "claude-code",
      p_key: `reason:${run}`, p_sources: [{ path: handler, sourceHash: hash(source) }], p_context: ctx });
    expect(args.p_instruction.length).toBeLessThanOrEqual(2000);
    expect(JSON.stringify(args.p_context)).not.toContain("Response.json");
    expect(mocks.file).not.toHaveBeenCalled();
  });

  it("offers nothing without a live approval for an agent host", async () => {
    for (const data of [null, { host: "codex", revoked_at: "2026-10-01T00:00:00Z", run_token_budget: 1000 },
      { host: "api", revoked_at: null, run_token_budget: 1000 }]) {
      mocks.read.mockResolvedValueOnce({ data, error: null });
      expect(await approvedAgent(user)).toBeNull();
    }
    expect(await approvedAgent(user)).toEqual(agent);
    expect(await offer(null)).toBeNull();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("treats a monthly limit as no task, and any other failure as an error", async () => {
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "intelligence budget exhausted" } });
    expect(await offer()).toBeNull();
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "audit unavailable" } });
    await expect(offer()).rejects.toThrow("reasoning_task_not_created");
  });
});

describe("submitReasoningResult", () => {
  it("refuses a malformed answer or one for another task, before storing anything", async () => {
    await expect(submitReasoningResult(user, reasoningTask(), { ...answer([]), extra: 1 })).rejects.toThrow("invalid_result");
    await expect(submitReasoningResult(user, reasoningTask(), { ...answer([]), identity: { ...identity, commit: "b".repeat(40) } }))
      .rejects.toThrow("scope_mismatch");
    await expect(submitReasoningResult(user, reasoningTask(), { ...answer([]), host: "api" })).rejects.toThrow("invalid_result");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("guards each hypothesis against the stored facts and asks for proof of what survives", async () => {
    const out = await submitReasoningResult(user, reasoningTask(), answer([hypothesis,
      { ...hypothesis, entry: "/api/invented" }, { ...hypothesis, citedFiles: ["lib/secret-helper.ts"] }]));
    expect(out).toMatchObject({ status: "proposal_received", admitted: 1, verificationTasks: [verifyId], findingsAdmitted: 0 });
    const stored = mocks.rpc.mock.calls.find(([name]) => name === "submit_intelligence_result")![1];
    expect(stored.p_status).toBe("proposal_received");
    expect(stored.p_result).toMatchObject({ rejected: 2, unmatchedEntries: ["/api/invented"],
      admitted: [{ entry: "/api/orders", attackClass: "missing_authentication", title: hypothesis.title }] });
    const verify = mocks.rpc.mock.calls.find(([name]) => name === "create_verification_task")![1];
    expect(verify).toMatchObject({ p_parent: taskId, p_key: `verify:${taskId}:0`, p_sources: [{ path: handler, sourceHash: hash(source) }] });
    expect(verify.p_context.items).toEqual([expect.objectContaining({ id: "0", entry: "/api/orders", handlerFile: handler })]);
    expect(mocks.file).toHaveBeenCalledWith("token", "acme/app", handler, commit);
  });

  it("creates no verification task when the guard admits nothing, and records an unavailable answer as such", async () => {
    expect(await submitReasoningResult(user, reasoningTask(), answer([{ ...hypothesis, entry: "/nope" }])))
      .toMatchObject({ admitted: 0, verificationTasks: [] });
    const unavailable = { version: 1, identity, host: "claude-code", model: "agent", usage: null, status: "unavailable", reason: "host_offline" };
    expect(await submitReasoningResult(user, reasoningTask(), unavailable)).toMatchObject({ status: "unavailable" });
    expect(mocks.rpc.mock.calls.filter(([name]) => name === "create_verification_task")).toEqual([]);
  });

  it("surfaces a stale or completed task as its code", async () => {
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "already_completed" } });
    await expect(submitReasoningResult(user, reasoningTask(), answer([hypothesis]))).rejects.toThrow("already_completed");
  });
});

describe("submitVerificationResult", () => {
  const items = [{ id: "0", entry: "/api/orders", attackClass: "missing_authentication", title: hypothesis.title,
    consequence: hypothesis.consequence, citedFiles: [handler], handlerFile: handler }];
  const verificationTask = (over: Partial<ReasoningTask> = {}) => reasoningTask({ id: verifyId, kind: "attack_verification",
    parent_task_id: taskId, context: { version: 1, hypotheses: [hypothesis], items }, ...over });
  const verdict = (over: Record<string, unknown> = {}) => ({ id: "0", verdict: "confirmed", severity: "critical",
    statement: "Anyone on the internet can read every customer's orders.", reason: "",
    citations: [{ role: "reach", path: handler, line: 1, quote: "export async function GET() {" },
      { role: "data", path: handler, line: 2, quote: "return Response.json(await db.from(\"orders\").select(\"*\"));" }], ...over });
  const verifyAnswer = (verdicts: unknown[]) => ({ version: 1, identity: { ...identity, taskId: verifyId }, host: "claude-code",
    model: "agent", usage: null, status: "proposed", verdicts });
  const admitted = () => mocks.rpc.mock.calls.find(([name]) => name === "admit_verified_findings")![1];

  it("admits a claim proved by quoted lines re-read from GitHub, worded by the verifier and capped without outside evidence", async () => {
    const out = await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict()]));
    expect(out).toMatchObject({ confirmed: 1, findingsAdmitted: 1 });
    const call = admitted();
    expect(call).toMatchObject({ p_user: user, p_task: verifyId, p_status: "proposal_received" });
    expect(call.p_findings).toEqual([expect.objectContaining({ id: "agent:missing_authentication:/api/orders",
      consequence: "Anyone on the internet can read every customer's orders.", severity: "WARNING" })]);
    expect(mocks.file).toHaveBeenCalledWith("token", "acme/app", handler, commit);
  });

  it("never lets the verifier's wording carry markup or control characters into a finding", async () => {
    for (const statement of ["<img src=x onerror=alert(1)> reads every order", "Reads orders\u0007", "x".repeat(401)]) {
      vi.clearAllMocks();
      mocks.rpc.mockResolvedValue({ data: "accepted", error: null });
      await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict({ statement: statement.slice(0, 600) })]));
      expect(admitted().p_findings).toEqual([expect.objectContaining({ consequence: expect.not.stringMatching(/[<>\u0000-\u001F]/) })]);
      expect(admitted().p_findings[0].consequence.length).toBeLessThanOrEqual(400);
    }
  });

  it("admits nothing when a quote is not on its line", async () => {
    await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict({ citations: [
      { role: "reach", path: handler, line: 1, quote: "export async function GET() {" },
      { role: "data", path: handler, line: 2, quote: "return Response.json(await db.from(\"users\").select(\"*\"));" }] })]));
    expect(admitted().p_findings).toEqual([]);
  });

  it("admits nothing when a claim cites a file it was not given", async () => {
    await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict({ citations: [
      { role: "reach", path: "lib/db.ts", line: 1, quote: "export const db = admin;" },
      { role: "data", path: handler, line: 2, quote: "return Response.json(await db.from(\"orders\").select(\"*\"));" }] })]));
    expect(admitted().p_findings).toEqual([]);
  });

  it("admits only the verified claim, never a deterministic finding the route facts also produce", async () => {
    const gap = { file: handler, method: "POST", model: "order", requires: [], expected: "admin", witness: { file: handler, method: "DELETE" },
      tier: "declared" as const };
    const withGap = { ...ctx, routes: [{ ...ctx.routes[0], permissionGaps: [gap] }] };
    mocks.read.mockImplementation(async (table: string) => table === "user_profiles"
      ? { data: { github_installation_id: 42 }, error: null } : { data: { context: withGap }, error: null });
    await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict()]));
    expect(admitted().p_findings.map((f: { id: string }) => f.id)).toEqual(["agent:missing_authentication:/api/orders"]);
  });

  it("refuses an answer when the cited file changed since the audit", async () => {
    mocks.file.mockResolvedValue(source + "// edited\n");
    await expect(submitVerificationResult(user, verificationTask(), verifyAnswer([verdict()]))).rejects.toThrow("source_changed");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("admits nothing for refuted, unverified or unavailable answers, and never a deterministic finding", async () => {
    await submitVerificationResult(user, verificationTask(), verifyAnswer([verdict({ verdict: "refuted", citations: [] })]));
    expect(admitted().p_findings).toEqual([]);
    vi.clearAllMocks();
    mocks.rpc.mockResolvedValue({ data: "accepted", error: null });
    const unavailable = { version: 1, identity: { ...identity, taskId: verifyId }, host: "claude-code", model: "agent", usage: null,
      status: "unavailable", reason: "quota_exhausted" };
    expect(await submitVerificationResult(user, verificationTask(), unavailable)).toMatchObject({ status: "unavailable", findingsAdmitted: 0 });
    expect(admitted()).toMatchObject({ p_status: "unavailable", p_findings: [] });
  });

  it("passes a stale audit through as task_stale", async () => {
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "task_stale" } });
    await expect(submitVerificationResult(user, verificationTask(), verifyAnswer([verdict()]))).rejects.toThrow("task_stale");
  });
});

describe("verificationBatches", () => {
  it("keeps at most ten claims and sixteen files per task", () => {
    const routes = Array.from({ length: 30 }, (_, i) => route({ path: `/api/r${i}`, file: `app/api/r${i}/route.ts` }));
    const many = routes.map((r) => ({ ...hypothesis, entry: r.path, citedFiles: [r.file], attackClass: "missing_authentication" as const }));
    const batches = verificationBatches(many, routes);
    expect(batches.every((b) => b.hypotheses.length <= 10 && b.files.length <= 16)).toBe(true);
    expect(batches.flatMap((b) => b.hypotheses)).toHaveLength(30);
  });
});

describe("taskBrief", () => {
  it("gives a reasoning agent the prompt and a verifier the claims, each with its own result schema", () => {
    const brief = taskBrief(reasoningTask());
    expect(brief).toMatchObject({ system: (ctx as ReasoningContext).system, prompt: ctx.prompt });
    expect(JSON.stringify(brief.resultSchema)).toContain("hypotheses");
    const verify = taskBrief(reasoningTask({ kind: "attack_verification", context: { version: 1, hypotheses: [hypothesis],
      items: [{ id: "0", entry: "/api/orders", attackClass: "missing_authentication", title: "t", consequence: "c", citedFiles: [handler] }] } }));
    expect(JSON.stringify(verify.resultSchema)).toContain("verdicts");
    expect(verify).toMatchObject({ claims: [{ id: "0", claim: "t. c" }] });
  });
});

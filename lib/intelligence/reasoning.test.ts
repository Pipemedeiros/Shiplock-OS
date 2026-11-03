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

import { approvedAgent, MAX_REASONING_PAGES, offerAuditReasoning, reasoningContext, reasoningPages, submitReasoningResult, submitVerificationResult, taskBrief,
  verificationBatches, verifyItems, middlewareFiles, type ReasoningContext, type ReasoningTask } from "./reasoning";

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

  it("stays well inside the task's 256 KB context limit on a very large repository", () => {
    const via = Array.from({ length: 500 }, (_, i) => `packages/shared/src/very/deep/module/path/number-${i}/index.ts`);
    const routes = Array.from({ length: 120 }, (_, i) => route({ path: `/api/resource-${i}/[id]/sub/[sub]`,
      file: `app/api/resource-${i}/[id]/sub/[sub]/route.ts`, via, tables: ["orders", "users", "invoices"] }));
    const big = context({ routes, files: [...routes.map((r) => r.file), ...via] })!;
    expect(Buffer.byteLength(JSON.stringify(big))).toBeLessThan(200_000);
    expect(big.routes.length).toBeGreaterThan(0);
    // The prompt lists exactly the routes the guard will accept.
    for (const r of big.routes) expect(big.prompt).toContain(`${r.path} id=`);
    expect(big.files.length).toBeLessThanOrEqual(2000);
  });

  it("asks nothing of an inventory-only stack or of routes that reach no table", () => {
    expect(context({ stack: { tools: [], authUnknown: true, databaseUnknown: true } as unknown as StackReport })).toBeNull();
    expect(context({ routes: [route({ tables: [] })] })).toBeNull();
  });
});

// Felipe 2026-10-08: "why would we not cover something?" A data route the
// agent never sees is a hole we cannot find. The ranked inventory is split
// into consecutive pages of MAX_PROMPT_ROUTES; nothing is dropped below the
// page bound, and each page is its own task.
describe("reasoningPages", () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => route({ path: `/api/r${String(i).padStart(3, "0")}`,
    file: `app/api/r${i}/route.ts` }));
  const pagesOf = (routes: RouteFact[]) => reasoningPages({ routes, stack: next, tables: ["orders"], files: routes.map((r) => r.file),
    liveFacts: [], possessionGates: new Map(), oneIdAccess: new Map(), hasDatabase: false });

  it("covers every data route once, in ranked order, sixty to a page", () => {
    const pages = pagesOf(many(130));
    expect(pages.map((p) => p.routes.length)).toEqual([60, 60, 10]);
    const seen = pages.flatMap((p) => p.routes.map((r) => r.path));
    expect(new Set(seen).size).toBe(130);
    expect(seen).toEqual([...seen].sort());
    for (const page of pages) for (const r of page.routes) expect(page.prompt).toContain(`${r.path} id=`);
    expect(pages[0]).toEqual(reasoningContext({ routes: many(130), stack: next, tables: ["orders"], files: many(130).map((r) => r.file),
      liveFacts: [], possessionGates: new Map(), oneIdAccess: new Map(), hasDatabase: false }));
  });

  it("moves what does not fit in a page's bytes to the next page instead of dropping it", () => {
    const via = Array.from({ length: 12 }, (_, i) => `packages/shared/src/a/very/long/module/path/for/size/number-${i}/index.ts`);
    const routes = Array.from({ length: 150 }, (_, i) => route({ path: `/api/resource-${String(i).padStart(3, "0")}/[id]/sub/[sub]/x`,
      file: `app/api/resource-${i}/[id]/sub/[sub]/x/route.ts`, via: via.map((v) => `${v}-${i}`), tables: ["orders", "users", "invoices"] }));
    const pages = pagesOf(routes);
    for (const page of pages) expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThanOrEqual(180_000);
    expect(pages.flatMap((p) => p.routes).length).toBe(150);
  });

  it("stops at the page bound, so a job stays bounded and the rest is disclosed", () => {
    const pages = pagesOf(many(MAX_REASONING_PAGES * 60 + 5));
    expect(pages).toHaveLength(MAX_REASONING_PAGES);
    expect(MAX_REASONING_PAGES * 60).toBeGreaterThanOrEqual(1000);
  });
});

describe("offerAuditReasoning", () => {
  const agent = { host: "claude-code" as const, runTokenBudget: 50000 };
  const offer = (approved: typeof agent | null = agent) => offerAuditReasoning({ userId: user, repositoryId: repo, runId: run, commit,
    fullName: "acme/app", contexts: [ctx], contents: new Map([[handler, source]]), agent: approved });

  it("creates one reasoning task per page, the first keyed by the audit alone", async () => {
    const second = { ...ctx, routes: [route({ path: "/api/second" })] };
    expect(await offerAuditReasoning({ userId: user, repositoryId: repo, runId: run, commit, fullName: "acme/app",
      contexts: [ctx, second], contents: new Map([[handler, source]]), agent })).toEqual([taskId, taskId]);
    expect(mocks.rpc.mock.calls.map(([, a]) => a.p_key)).toEqual([`reason:${run}`, `reason:${run}:2`]);
    expect(mocks.rpc.mock.calls[1][1].p_instruction).toMatch(/part 2 of 2/);
  });

  it("stops creating pages when the monthly limit is reached, keeping what was created", async () => {
    mocks.rpc.mockResolvedValueOnce({ data: taskId, error: null }).mockResolvedValueOnce({ data: null, error: { message: "intelligence budget exhausted" } });
    expect(await offerAuditReasoning({ userId: user, repositoryId: repo, runId: run, commit, fullName: "acme/app",
      contexts: [ctx, ctx, ctx], contents: new Map([[handler, source]]), agent })).toEqual([taskId]);
    expect(mocks.rpc).toHaveBeenCalledTimes(2);
  });

  it("creates one reasoning task per audit for the approved host, hashing handlers from the audit's own archive", async () => {
    expect(await offer()).toEqual([taskId]);
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
    expect(await offer(null)).toEqual([]);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("treats a monthly limit as no task, and any other failure as an error", async () => {
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "intelligence budget exhausted" } });
    expect(await offer()).toEqual([]);
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
    expect(verify).toMatchObject({ p_parent: taskId, p_key: `verify:${taskId}:0`, p_sources: [{ path: handler, sourceHash: hash(source) },
      { path: "prisma/schema.prisma", sourceHash: hash(source) }] }); // the schema goes with every batch
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

  // A batched corpus run (2026-10-09): a claim on a query the schema rejects was
  // "confirmed" because the verifier never saw the schema. The schema files
  // the audit read go with every batch (at most two), inside the file cap.
  it("lists the schema with every batch so a claim can be checked against it", () => {
    const routes = Array.from({ length: 12 }, (_, i) => route({ path: `/api/r${i}`, file: `app/api/r${i}/route.ts` }));
    const many = routes.map((r) => ({ ...hypothesis, entry: r.path, citedFiles: [r.file], attackClass: "missing_authentication" as const }));
    const schema = ["prisma/schema.prisma", "db/extra.sql", "db/third.sql"];
    const batches = verificationBatches(many, routes, schema);
    for (const b of batches) {
      expect(b.files).toEqual(expect.arrayContaining(["prisma/schema.prisma", "db/extra.sql"]));
      expect(b.files).not.toContain("db/third.sql");
      expect(b.files.length).toBeLessThanOrEqual(16);
    }
    expect(batches.flatMap((b) => b.hypotheses)).toHaveLength(12);
    expect(verificationBatches(many.slice(0, 1), routes)[0].files).toEqual(["app/api/r0/route.ts"]);
  });
});

// X1 (2026-10-12): the live database reaches the verifier. Facts read from
// the connected database for the tables a claim's route reaches go with the
// claim, so a row policy is an observation instead of "unverified"; an open
// table also becomes a cited live claim on the finding.
describe("verifyItems", () => {
  const facts = [
    { id: "db:public.orders:rls-off", statement: "row security is off on public.orders" },
    { id: "db:public.users:rls-filtered", statement: "row security is on for public.users" },
    { id: "db:public.notes:open-policy", statement: "a policy on public.notes matches every row" },
    { id: "vercel:project:p:env:STRIPE_SECRET_KEY", statement: "STRIPE_SECRET_KEY set in production" },
  ];
  const routes = [route({ path: "/api/orders", tables: ["orders", "users"] })];
  const h = { ...hypothesis, attackClass: "missing_authentication" as const };

  it("lists the facts for the route's tables with the claim and cites only the open ones", () => {
    const out = verifyItems([h], routes, facts);
    expect(out.items[0].facts?.map((f) => f.id)).toEqual(["db:public.orders:rls-off", "db:public.users:rls-filtered"]);
    expect((out.hypotheses[0] as { citedFacts?: string[] }).citedFacts).toEqual(["db:public.orders:rls-off"]);
  });

  it("keeps a fact the agent cited, and adds nothing where nothing was read", () => {
    const cited = { ...h, citedFacts: ["vercel:project:p:env:STRIPE_SECRET_KEY"] };
    expect(verifyItems([cited], routes, facts).items[0].facts?.map((f) => f.id))
      .toEqual(["vercel:project:p:env:STRIPE_SECRET_KEY", "db:public.orders:rls-off", "db:public.users:rls-filtered"]);
    const none = verifyItems([h], routes, []);
    expect(none.items[0]).not.toHaveProperty("facts");
    expect(none.hypotheses[0]).toBe(h);
  });

  it("shows the verifier the facts in its brief", () => {
    const { hypotheses, items } = verifyItems([h], routes, facts);
    const brief = taskBrief(reasoningTask({ kind: "attack_verification", context: { version: 1, hypotheses, items } }));
    expect(brief.claims?.[0]).toMatchObject({ facts: [{ id: "db:public.orders:rls-off" }, { id: "db:public.users:rls-filtered" }] });
    expect(brief.system).toMatch(/connected database/);
  });
});

// Release attempt 3 (2026-10-13): the verifier confirmed "any caller can
// list every profile" where middleware.ts, never shown to it, requires
// sign-in. The root middleware goes with every batch, like the schema.
describe("middleware with every verification batch", () => {
  it("lists the root middleware beside the schema, within the file cap", () => {
    const routes = Array.from({ length: 12 }, (_, i) => route({ path: `/api/r${i}`, file: `app/api/r${i}/route.ts` }));
    const many = routes.map((r) => ({ ...hypothesis, entry: r.path, citedFiles: [r.file], attackClass: "missing_authentication" as const }));
    const batches = verificationBatches(many, routes, ["prisma/schema.prisma"], ["src/middleware.ts"]);
    for (const b of batches) {
      expect(b.files).toEqual(expect.arrayContaining(["src/middleware.ts", "prisma/schema.prisma"]));
      expect(b.files.length).toBeLessThanOrEqual(16);
    }
  });

  it("finds only the root middleware or proxy file", () => {
    expect(middlewareFiles(["middleware.ts", "src/middleware.ts", "lib/middleware.ts", "proxy.ts", "app/api/x/route.ts"]))
      .toEqual(["middleware.ts", "src/middleware.ts", "proxy.ts"]);
  });

  it("puts the middleware in the reasoning context's files even when no route imports it", () => {
    const pages = reasoningPages({ routes: [route()], stack: (ctx as ReasoningContext).stack, tables: ["orders"],
      files: [handler, "middleware.ts", "README.md"], liveFacts: [], possessionGates: new Map(), oneIdAccess: new Map(), hasDatabase: true });
    expect(pages[0].files).toContain("middleware.ts");
    expect(pages[0].files).not.toContain("README.md");
  });

  it("tells the verifier to read the middleware before claiming anonymous reach", () => {
    expect(taskBrief(reasoningTask({ kind: "attack_verification", context: { version: 1, hypotheses: [hypothesis], items: [] } })).system)
      .toMatch(/middleware file is listed.*matcher/i);
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

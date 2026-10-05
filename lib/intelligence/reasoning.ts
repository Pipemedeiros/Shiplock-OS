import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getFile, getInstallationToken } from "@/lib/deep/github";
import { buildPrompt, MAX_PROMPT_ROUTES, rankRoutes, SYSTEM, type AgentInput } from "@/lib/agent/attack";
import { guardHypotheses, type AttackClass, type Hypothesis } from "@/lib/agent/attackGuard";
import { buildFindings } from "@/lib/agent/findings";
import type { PossessionGate } from "@/lib/agent/possessionGate";
import { routeAnalysisSupport, type StackReport } from "@/lib/agent/stack";
import { applyVerdicts, checkVerdicts, VERIFY_SYSTEM, type RawVerdict, type VerifyItem } from "@/lib/agent/verify";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { sourceHash } from "./exchange";

// Audit reasoning on the customer's own agent (Felipe, 2026-10-01: ShipLock
// makes no model call). Two tasks, both answered over MCP:
//
//  1. attack_reasoning: the audit's ranked route inventory and the prompt the
//     corpus measures. The answer is a hypothesis array, judged by the same
//     deterministic guard as ever against the facts stored on the task (never
//     facts the agent supplies).
//  2. attack_verification: each admitted hypothesis, with the files to read.
//     The agent proves reach and data with quoted lines; ShipLock re-reads
//     those lines from GitHub at the audit's commit. Only confirmed claims
//     become findings, for the newest complete audit, and only ever added.
//
// The context stored on a task is ShipLock's own observation: route facts,
// paths, tables, live fact statements, the prompt. Never source, never a
// secret, never a row value.

const MAX_FILES = 2_000;
const MAX_HYPOTHESES = 60;
const VERIFY_BATCH = 10;
const MAX_SOURCES = 16;
const TASK_MINUTES = 23 * 60;

type Gate = PossessionGate;
export type ReasoningContext = {
  version: 1; system: string; prompt: string; routes: RouteFact[]; files: string[]; tables: string[];
  liveFacts: { id: string; statement: string }[]; possessionGates: [string, Gate][]; oneIdAccess: [string, Gate][];
  stack: StackReport; hasDatabase: boolean;
};
type VerificationContext = { version: 1; hypotheses: (Hypothesis & { attackClass: AttackClass })[]; items: VerifyItem[] };

/**
 * What the agent reasons over: the routes that reach data, ranked and capped
 * exactly as the prompt shows them, and the files a hypothesis may cite (those
 * routes' handlers and the modules their facts came from, plus schema files).
 * Null when there is nothing to ask: a framework we only inventory, or no
 * route that reaches a table.
 */
export function reasoningContext(input: {
  routes: RouteFact[]; stack: StackReport; tables: string[]; files: string[]; domain?: AgentInput["domain"];
  liveFacts: { id: string; statement: string }[]; possessionGates: ReadonlyMap<string, Gate>;
  oneIdAccess: ReadonlyMap<string, Gate>; hasDatabase: boolean;
}): ReasoningContext | null {
  if (routeAnalysisSupport(input.stack).level !== "deep") return null;
  const shown = rankRoutes(input.routes.filter((r) => r.tables.length > 0), new Set(input.domain?.sensitive ?? []))
    .slice(0, MAX_PROMPT_ROUTES);
  if (shown.length === 0) return null;
  const onShown = new Set(shown.map((r) => r.path));
  const schema = input.files.filter((f) => /(^|\/)schema\.prisma$|\.sql$|(^|\/)schema\.[cm]?[jt]s$/.test(f));
  const files = [...new Set([...shown.flatMap((r) => [r.file, ...r.via]), ...schema])].slice(0, MAX_FILES);
  const pick = (gates: ReadonlyMap<string, Gate>) => [...gates].filter(([path]) => onShown.has(path));
  return {
    version: 1, system: SYSTEM,
    prompt: buildPrompt({ routes: shown, stack: input.stack, tables: input.tables, files, domain: input.domain, liveFacts: input.liveFacts }),
    routes: shown, files, tables: input.tables, liveFacts: input.liveFacts.slice(0, 20),
    possessionGates: pick(input.possessionGates), oneIdAccess: pick(input.oneIdAccess),
    stack: input.stack, hasDatabase: input.hasDatabase,
  };
}

const connectionSchema = z.object({ host: z.enum(["claude-code", "codex", "chatgpt", "api"]), revoked_at: z.string().nullable(),
  run_token_budget: z.number().int().positive() });

export type ApprovedAgent = { host: "claude-code" | "codex" | "chatgpt"; runTokenBudget: number };

/** The customer's live approval for an agent host, or null (none, revoked,
 * or the retired API-key mode). */
export async function approvedAgent(userId: string): Promise<ApprovedAgent | null> {
  const { data, error } = await getSupabaseAdmin().from("intelligence_connections").select("host, revoked_at, run_token_budget")
    .eq("user_id", userId).maybeSingle();
  if (error) throw new Error("connection_unreadable");
  const connection = connectionSchema.safeParse(data);
  if (!connection.success || connection.data.revoked_at || connection.data.host === "api") return null;
  return { host: connection.data.host, runTokenBudget: connection.data.run_token_budget };
}

/**
 * After a complete audit: ask the customer's approved agent to reason over it.
 * Best effort and never fatal, because the audit is already durable; the
 * Coverage note says reasoning has not run until an answer is admitted. The
 * handler files' hashes come from the audit's own archive at its commit.
 */
export async function offerAuditReasoning(input: {
  userId: string; repositoryId: string; runId: string; commit: string; fullName: string;
  context: ReasoningContext | null; contents: ReadonlyMap<string, string>; agent: ApprovedAgent | null;
}): Promise<string | null> {
  if (!input.context || !input.agent) return null;
  const admin = getSupabaseAdmin();
  const sources = [...new Set(input.context.routes.map((r) => r.file))]
    .filter((path) => input.contents.has(path)).slice(0, MAX_SOURCES)
    .map((path) => ({ path, sourceHash: sourceHash(input.contents.get(path)!) }));
  if (sources.length === 0) return null;
  const instruction = `Attack reasoning for the audit of ${input.fullName} at ${input.commit.slice(0, 12)}: `
    + `${input.context.routes.length} routes that reach data. Read system and prompt, reason over your own checkout at `
    + "this commit, and answer with hypotheses: a JSON array as system describes, at most 60. Cite only routes, files, "
    + "tables and fact ids that appear in the prompt. ShipLock checks every hypothesis, then asks you to prove each one "
    + "with quoted lines before it becomes a finding. If you cannot finish, answer unavailable; never report clean for "
    + `what you did not read. Stay within ${input.agent.runTokenBudget} tokens for this task.`;
  const { data: id, error: createError } = await admin.rpc("create_audit_reasoning_task", {
    p_user: input.userId, p_repository: input.repositoryId, p_run: input.runId, p_commit: input.commit,
    p_host: input.agent.host, p_instruction: instruction, p_sources: sources, p_context: input.context,
    p_expires_at: new Date(Date.now() + TASK_MINUTES * 60_000).toISOString(), p_key: `reason:${input.runId}`,
  });
  if (createError) {
    if (/intelligence not approved|intelligence budget exhausted/.test(createError.message)) return null;
    throw new Error("reasoning_task_not_created");
  }
  return z.uuid().parse(id);
}

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const identity = z.object({ taskId: z.uuid(), tenantId: z.uuid(), repositoryId: z.uuid(), commit: z.string().regex(/^[a-f0-9]{40}$/) }).strict();
const host = z.enum(["codex", "claude-code", "chatgpt"]);
const usage = z.object({ inputTokens: z.number().int().min(0).max(10_000_000), outputTokens: z.number().int().min(0).max(10_000_000) }).strict().nullable();
const answered = { version: z.literal(1), identity, host, model: z.string().min(1).max(100), usage };

export const reasoningResultSchema = z.discriminatedUnion("status", [
  z.object({ ...answered, status: z.literal("proposed"), hypotheses: z.array(z.unknown()).max(MAX_HYPOTHESES),
    truncated: z.boolean() }).strict(),
  z.object({ ...answered, status: z.literal("unavailable"), reason: z.enum(["host_offline", "quota_exhausted", "unsupported", "cancelled"]) }).strict(),
]);

const citation = z.object({ role: z.enum(["reach", "data", "control"]), path: z.string().min(1).max(240), line: z.number().int().min(1),
  quote: z.string().min(1).max(2_000) }).strict();
export const verificationResultSchema = z.discriminatedUnion("status", [
  z.object({ ...answered, status: z.literal("proposed"), verdicts: z.array(z.object({
    id: z.string().max(10), verdict: z.enum(["confirmed", "refuted", "unverified"]), severity: z.enum(["critical", "high", "medium"]),
    statement: z.string().max(600), reason: z.string().max(1_000), citations: z.array(citation).max(12),
  }).strict()).max(VERIFY_BATCH) }).strict(),
  z.object({ ...answered, status: z.literal("unavailable"), reason: z.enum(["host_offline", "quota_exhausted", "unsupported", "cancelled"]) }).strict(),
]);

export type ReasoningTask = {
  id: string; user_id: string; repository_id: string; commit_sha: string; host: string; kind: string;
  audit_run_id: string | null; parent_task_id: string | null; context: unknown;
  sources: { path: string; sourceHash: string }[]; repositories: { full_name: string };
};

const contextSchema = z.object({ version: z.literal(1), system: z.string(), prompt: z.string(), routes: z.array(z.any()),
  files: z.array(z.string()), tables: z.array(z.string()), liveFacts: z.array(z.object({ id: z.string(), statement: z.string() })),
  possessionGates: z.array(z.tuple([z.string(), z.any()])), oneIdAccess: z.array(z.tuple([z.string(), z.any()])),
  stack: z.any(), hasDatabase: z.boolean() });
const verificationContextSchema = z.object({ version: z.literal(1), hypotheses: z.array(z.any()), items: z.array(z.any()) });

/** What the agent reads for a reasoning or verification task. */
export function taskBrief(task: ReasoningTask) {
  if (task.kind === "attack_reasoning") {
    const context = contextSchema.parse(task.context);
    return { system: context.system, prompt: context.prompt, resultSchema: z.toJSONSchema(reasoningResultSchema),
      limits: { hypotheses: MAX_HYPOTHESES, resultBytes: 64_000 } };
  }
  const context = verificationContextSchema.parse(task.context);
  const claims = (context.items as VerifyItem[]).map((item) => ({ id: item.id, entry: item.entry, attackClass: item.attackClass,
    claim: `${item.title}. ${item.consequence}`, handlerFile: item.handlerFile ?? null, citedFiles: item.citedFiles }));
  return { system: VERIFY_SYSTEM, claims, resultSchema: z.toJSONSchema(verificationResultSchema),
    limits: { verdicts: VERIFY_BATCH, citationsPerVerdict: 12, resultBytes: 64_000 },
    note: "Read only the listed files at this commit. Cite each line by its 1-based number in that file and quote it exactly. A claim that depends on any file not listed is unverified." };
}

function checkIdentity(task: ReasoningTask, result: { identity: z.infer<typeof identity>; host: string }) {
  if (result.identity.taskId !== task.id || result.identity.tenantId !== task.user_id
    || result.identity.repositoryId !== task.repository_id || result.identity.commit !== task.commit_sha || result.host !== task.host) {
    throw new Error("scope_mismatch");
  }
}

function rpcError(message: string): Error {
  const code = ["task_expired", "task_scope_changed", "already_completed", "task_stale"].find((c) => message.includes(c));
  return new Error(code ?? "task_unavailable");
}

async function installationToken(userId: string): Promise<string> {
  const { data } = await getSupabaseAdmin().from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle();
  const installationId = data?.github_installation_id as number | null | undefined;
  if (!installationId) throw new Error("task_scope_changed");
  return getInstallationToken(installationId);
}

/**
 * Judges a reasoning answer and, for what the guard admits, asks for proof.
 * The admitted hypotheses are stored on the task and are never findings on
 * their own. Verification tasks are idempotent per batch, so a replayed
 * answer (a lost acknowledgement) recreates nothing twice.
 */
export async function submitReasoningResult(userId: string, task: ReasoningTask, raw: unknown) {
  const parsed = reasoningResultSchema.safeParse(raw);
  if (!parsed.success) throw new Error("invalid_result");
  const result = parsed.data;
  checkIdentity(task, result);
  const context = contextSchema.parse(task.context) as unknown as ReasoningContext;
  const digest = sourceHash(JSON.stringify(result));
  const admin = getSupabaseAdmin();

  if (result.status === "unavailable") {
    const { data, error } = await admin.rpc("submit_intelligence_result", { p_user: userId, p_task: task.id, p_status: "unavailable",
      p_result: { status: "unavailable", reason: result.reason, model: result.model, usage: result.usage }, p_digest: digest });
    if (error) throw rpcError(error.message);
    return { taskId: task.id, status: "unavailable" as const, outcome: data === "replayed" ? "replayed" as const : "accepted" as const,
      admitted: 0, verificationTasks: [] as string[], findingsAdmitted: 0 as const };
  }

  const guard = guardHypotheses(result.hypotheses, {
    entries: new Set(context.routes.map((r) => r.path)), files: new Set(context.files), tables: new Set(context.tables),
    facts: new Set(context.liveFacts.map((f) => f.id)), routes: new Map(context.routes.map((r) => [r.path, r])),
    possessionGates: new Map(context.possessionGates),
  });
  const stored = { status: "proposed", model: result.model, usage: result.usage, truncated: result.truncated,
    // References only; each verification task carries its own hypotheses.
    admitted: guard.admitted.map((h) => ({ entry: h.entry, attackClass: h.attackClass, title: h.title })),
    rejected: guard.rejected.length, unassessed: guard.unassessed.slice(0, 60),
    unmatchedEntries: guard.unmatchedEntries.slice(0, 20) };
  const { data, error } = await admin.rpc("submit_intelligence_result", { p_user: userId, p_task: task.id,
    p_status: "proposal_received", p_result: stored, p_digest: digest });
  if (error) throw rpcError(error.message);

  const verificationTasks: string[] = [];
  if (guard.admitted.length > 0) {
    const token = await installationToken(userId);
    const read = new Map<string, string | null>();
    const contentOf = async (path: string) => {
      if (!read.has(path)) read.set(path, await getFile(token, task.repositories.full_name, path, task.commit_sha));
      return read.get(path) ?? null;
    };
    for (const [index, batch] of verificationBatches(guard.admitted, context.routes).entries()) {
      const sources: { path: string; sourceHash: string }[] = [];
      for (const path of batch.files) {
        const content = await contentOf(path);
        if (content !== null) sources.push({ path, sourceHash: sourceHash(content) });
      }
      if (sources.length === 0) continue;
      const items = batch.hypotheses.map((h, i): VerifyItem => ({ id: String(i), entry: h.entry, attackClass: h.attackClass,
        title: h.title, consequence: h.consequence, citedFiles: h.citedFiles ?? [],
        handlerFile: context.routes.find((r) => r.path === h.entry)?.file }));
      const { data: id, error: verifyError } = await admin.rpc("create_verification_task", { p_user: userId, p_parent: task.id,
        p_instruction: `Verify ${items.length} attack ${items.length === 1 ? "claim" : "claims"} on ${task.repositories.full_name} at `
          + `${task.commit_sha.slice(0, 12)}. Most claims are wrong. Confirm one only when quoted lines from the listed files prove reach, `
          + "data and no control; refute it when the code shows a check; answer unverified when it depends on anything not listed.",
        p_sources: sources, p_context: { version: 1, hypotheses: batch.hypotheses, items }, p_key: `verify:${task.id}:${index}` });
      if (verifyError) {
        if (/intelligence not approved|intelligence budget exhausted/.test(verifyError.message)) break;
        throw rpcError(verifyError.message);
      }
      verificationTasks.push(z.uuid().parse(id));
    }
  }
  return { taskId: task.id, status: "proposal_received" as const, outcome: data === "replayed" ? "replayed" as const : "accepted" as const,
    admitted: guard.admitted.length, verificationTasks, findingsAdmitted: 0 as const };
}

/** Admitted hypotheses in batches of at most VERIFY_BATCH claims whose
 * handler and cited files together fit in MAX_SOURCES listed files. */
export function verificationBatches(admitted: (Hypothesis & { attackClass: AttackClass })[], routes: RouteFact[]) {
  const batches: { hypotheses: (Hypothesis & { attackClass: AttackClass })[]; files: string[] }[] = [];
  for (const h of admitted) {
    const handler = routes.find((r) => r.path === h.entry)?.file;
    const needed = [...new Set([handler, ...(h.citedFiles ?? [])].filter((f): f is string => Boolean(f)))].slice(0, MAX_SOURCES);
    const open = batches.find((b) => b.hypotheses.length < VERIFY_BATCH
      && new Set([...b.files, ...needed]).size <= MAX_SOURCES);
    if (open) { open.hypotheses.push(h); open.files = [...new Set([...open.files, ...needed])]; }
    else batches.push({ hypotheses: [h], files: needed });
  }
  return batches;
}

/**
 * Checks a verification answer and admits what it proved. Every cited line is
 * re-read from GitHub at the audit's commit and must match its listed hash; a
 * quote that is not on its line, or a citation of an unlisted file, leaves the
 * claim unverified. Findings carry the class's severity ceilings, including
 * the repository-only cap at WARNING.
 */
export async function submitVerificationResult(userId: string, task: ReasoningTask, raw: unknown) {
  const parsed = verificationResultSchema.safeParse(raw);
  if (!parsed.success) throw new Error("invalid_result");
  const result = parsed.data;
  checkIdentity(task, result);
  const digest = sourceHash(JSON.stringify(result));
  const admin = getSupabaseAdmin();
  const admit = async (status: "proposal_received" | "unavailable", stored: Record<string, unknown>, findings: unknown[]) => {
    const { data, error } = await admin.rpc("admit_verified_findings", { p_user: userId, p_task: task.id, p_status: status,
      p_result: stored, p_digest: digest, p_findings: findings });
    if (error) throw rpcError(error.message);
    return data === "replayed" ? "replayed" as const : "accepted" as const;
  };
  if (result.status === "unavailable") {
    const outcome = await admit("unavailable", { status: "unavailable", reason: result.reason, model: result.model, usage: result.usage }, []);
    return { taskId: task.id, status: "unavailable" as const, outcome, confirmed: 0, refuted: 0, unverified: 0, findingsAdmitted: 0 };
  }

  const verification = verificationContextSchema.parse(task.context) as unknown as VerificationContext;
  const { data: parent, error: parentError } = await admin.from("intelligence_tasks").select("context")
    .eq("id", task.parent_task_id).eq("user_id", userId).eq("kind", "attack_reasoning").maybeSingle();
  if (parentError || !parent) throw new Error("task_unavailable");
  const context = contextSchema.parse(parent.context) as unknown as ReasoningContext;

  const listed = new Map(task.sources.map((s) => [s.path, s.sourceHash]));
  const cited = [...new Set(result.verdicts.flatMap((v) => v.citations.map((c) => c.path)).filter((p) => listed.has(p)))];
  const files = new Map<string, string>();
  if (cited.length > 0) {
    const token = await installationToken(userId);
    for (const path of cited) {
      const content = await getFile(token, task.repositories.full_name, path, task.commit_sha);
      if (content === null) throw new Error("source_unreadable");
      if (sourceHash(content) !== listed.get(path)) throw new Error("source_changed");
      files.set(path, content);
    }
  }
  const verdicts = checkVerdicts(result.verdicts as RawVerdict[], verification.items, files, new Set(listed.keys()));
  const applied = applyVerdicts(verification.hypotheses, verdicts);
  const findings = buildFindings({
    admitted: applied.kept, deterministic: [], routes: context.routes, stack: context.stack, repositoryId: task.repository_id,
    hasDatabase: context.hasDatabase, liveFacts: context.liveFacts, possessionGates: new Map(context.possessionGates),
    oneIdAccess: new Map(context.oneIdAccess),
  }).filter((f) => f.attackClass !== "permission_gap" && f.attackClass !== "committed_secret");
  const stored = { status: "proposed", model: result.model, usage: result.usage,
    verdicts: verdicts.map((v) => ({ id: v.id, verdict: v.verdict, citationProblem: v.citationProblem })),
    confirmed: applied.kept.length, refuted: applied.refuted, unverified: applied.unverified };
  const outcome = await admit("proposal_received", stored, findings);
  return { taskId: task.id, status: "proposal_received" as const, outcome, confirmed: applied.kept.length, refuted: applied.refuted,
    unverified: applied.unverified, findingsAdmitted: findings.length };
}

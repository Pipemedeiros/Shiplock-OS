import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getFile, getInstallationToken } from "@/lib/deep/github";
import { judgeEdit } from "@/lib/agent/editGuard";
import {
  addSecurityHeaders, addWorkflowPermissions, disableProductionSourceMaps, removeSecretLogging, type Codemod,
} from "@/lib/fixes/codemods";
import { checkResultEvidence, intelligenceResultSchema, sourceHash, type SourceFile } from "./exchange";
import { submitReasoningResult, submitVerificationResult, taskBrief, type ReasoningTask } from "./reasoning";

// Durable customer-intelligence tasks (10B-1b). A customer's own agent reads a
// task, reasons over its own checkout, and submits one
// result. ShipLock stores paths and hashes, never source, and re-reads every
// cited file from GitHub at the pinned commit before accepting anything. A
// result is a proposal: nothing here applies an edit, opens a PR, or funds a
// model call, and self-reported usage is never treated as verified. "api" is
// the retired customer API-key mode (Felipe, 2026-10-01): its old rows are
// read, never offered to an agent and never answered.

const durableResultSchema = intelligenceResultSchema.extend({
  identity: z.object({
    taskId: z.uuid(), tenantId: z.uuid(), repositoryId: z.uuid(), commit: z.string().regex(/^[a-f0-9]{40}$/),
  }).strict(),
  host: z.enum(["codex", "claude-code", "chatgpt"]),
}).strict();
const taskRowSchema = z.object({
  id: z.uuid(), user_id: z.uuid(), repository_id: z.uuid(), commit_sha: z.string(),
  host: z.enum(["codex", "claude-code", "chatgpt", "api"]), instruction: z.string(),
  sources: z.array(z.object({ path: z.string(), sourceHash: z.string() })),
  status: z.enum(["pending", "proposal_received", "needs_human", "unavailable", "cancelled"]),
  result: z.unknown().nullable(), expires_at: z.string(),
  repositories: z.object({ full_name: z.string() }),
  // Review tasks (deep and PR scans) or audit reasoning and its verification
  // (lib/intelligence/reasoning.ts, migration 098).
  kind: z.enum(["review", "attack_reasoning", "attack_verification"]),
  audit_run_id: z.uuid().nullable(), parent_task_id: z.uuid().nullable(), context: z.unknown().nullable(),
});
type TaskRow = z.infer<typeof taskRowSchema>;

/** Mechanical edits a host may propose in 10B-1: exactly what one of these
 * parameterless codemods would produce, and accepted by the edit guard.
 * Anything else (including authorization logic) needs a human. */
const MECHANICAL: readonly Codemod[] = [disableProductionSourceMaps, addSecurityHeaders, addWorkflowPermissions, removeSecretLogging];
export function mechanicalEdit(file: Readonly<SourceFile>, proposed: string): boolean {
  return MECHANICAL.some((codemod) => codemod({ path: file.path, content: file.content }, {} as never)?.content === proposed)
    && judgeEdit(file.path, file.content, proposed).safe;
}

async function loadTask(userId: string, taskId: string): Promise<TaskRow | null> {
  const { data, error } = await getSupabaseAdmin().from("intelligence_tasks")
    .select("id, user_id, repository_id, commit_sha, host, instruction, sources, status, result, expires_at, kind, audit_run_id, parent_task_id, context, repositories(full_name)")
    .eq("id", taskId).eq("user_id", userId).maybeSingle();
  if (error) throw new Error("task_unreadable");
  const row = taskRowSchema.safeParse(data);
  return row.success ? row.data : null;
}

export async function getIntelligenceTask(userId: string, taskId: string) {
  const task = await loadTask(userId, taskId);
  if (!task) return null;
  const expired = task.status === "pending" && Date.parse(task.expires_at) <= Date.now();
  return {
    version: 1,
    identity: { taskId: task.id, tenantId: task.user_id, repositoryId: task.repository_id, commit: task.commit_sha },
    host: task.host, repository: task.repositories.full_name, instruction: task.instruction,
    // Paths and hashes only: the agent reads its own checkout at this commit.
    sources: task.sources, permission: "propose_only" as const,
    // The agent spends its own allowance; ShipLock does not verify who paid.
    funding: "unverified" as const,
    status: expired ? "expired" as const : task.status, expiresAt: task.expires_at, kind: task.kind,
    ...(task.kind === "review"
      ? { limits: { citations: 16, edits: 3, resultBytes: 64_000 }, resultSchema: z.toJSONSchema(durableResultSchema) }
      : taskBrief(task as ReasoningTask)),
  };
}

export async function submitIntelligenceResult(userId: string, taskId: string, raw: unknown) {
  let bytes: string | undefined;
  try { bytes = JSON.stringify(raw); } catch { throw new Error("invalid_result"); }
  if (bytes && Buffer.byteLength(bytes) > 64_000) throw new Error("result_too_large");
  const loaded = await loadTask(userId, taskId);
  if (!loaded || loaded.host === "api") throw new Error("task_unavailable");
  if (loaded.kind === "attack_reasoning") return submitReasoningResult(userId, loaded as ReasoningTask, raw);
  if (loaded.kind === "attack_verification") return submitVerificationResult(userId, loaded as ReasoningTask, raw);
  const parsed = durableResultSchema.safeParse(raw);
  if (!parsed.success) throw new Error("invalid_result");
  const result = parsed.data;
  const task = loaded;
  if (result.identity.taskId !== task.id || result.identity.tenantId !== task.user_id
      || result.identity.repositoryId !== task.repository_id || result.identity.commit !== task.commit_sha
      || result.host !== task.host) {
    throw new Error("scope_mismatch");
  }

  // Re-read only cited or edited listed files, at the pinned commit.
  const listed = new Map(task.sources.map((source) => [source.path, source.sourceHash]));
  const needed = [...new Set([...result.citations.map((c) => c.path), ...result.edits.map((e) => e.path)])];
  for (const path of needed) if (!listed.has(path)) throw new Error("source_not_allowed");
  const files = new Map<string, SourceFile>();
  if (needed.length) {
    const { data: profile } = await getSupabaseAdmin().from("user_profiles")
      .select("github_installation_id").eq("id", userId).maybeSingle();
    const installationId = profile?.github_installation_id as number | null | undefined;
    if (!installationId) throw new Error("task_scope_changed");
    const token = await getInstallationToken(installationId);
    for (const path of needed) {
      const content = await getFile(token, task.repositories.full_name, path, task.commit_sha);
      if (content === null) throw new Error("source_unreadable");
      if (sourceHash(content) !== listed.get(path)) throw new Error("source_changed");
      files.set(path, { path, content });
    }
  }
  checkResultEvidence(result, (path) => {
    const file = files.get(path);
    if (!file) throw new Error("source_not_allowed");
    return file;
  }, mechanicalEdit);

  const status = result.status === "proposed" ? "proposal_received" : result.status;
  const digest = sourceHash(JSON.stringify(result));
  const { data, error } = await getSupabaseAdmin().rpc("submit_intelligence_result", {
    p_user: userId, p_task: taskId, p_status: status, p_result: result, p_digest: digest,
  });
  if (error) {
    const code = ["task_expired", "task_scope_changed", "already_completed"].find((c) => error.message.includes(c));
    throw new Error(code ?? "task_unavailable");
  }
  return { taskId, status, outcome: data === "replayed" ? "replayed" as const : "accepted" as const,
    applied: false as const, prOpened: false as const, tests: "not_run" as const, modelUsageVerified: false as const };
}

/** Admit a task (10B-1b). Each listed file is read from GitHub at the commit
 * and hashed by ShipLock, so a host can never supply the hashes it will later
 * be checked against. Idempotent per `key`. */
export async function createIntelligenceTask(input: {
  userId: string; repositoryId: string; commit: string; host: "codex" | "claude-code" | "chatgpt";
  instruction: string; paths: string[]; minutes: number; key: string;
}): Promise<string> {
  const admin = getSupabaseAdmin();
  const [{ data: repository }, { data: profile }] = await Promise.all([
    admin.from("repositories").select("full_name").eq("id", input.repositoryId)
      .eq("user_id", input.userId).eq("selected", true).maybeSingle(),
    admin.from("user_profiles").select("github_installation_id").eq("id", input.userId).maybeSingle(),
  ]);
  const installationId = profile?.github_installation_id as number | null | undefined;
  if (!repository || !installationId) throw new Error("repository_unavailable");
  const token = await getInstallationToken(installationId);
  const sources: { path: string; sourceHash: string }[] = [];
  for (const path of input.paths) {
    const content = await getFile(token, repository.full_name as string, path, input.commit);
    if (content === null) throw new Error("source_unreadable");
    sources.push({ path, sourceHash: sourceHash(content) });
  }
  const { data, error } = await admin.rpc("create_intelligence_task", {
    p_user: input.userId, p_repository: input.repositoryId, p_commit: input.commit, p_host: input.host,
    p_instruction: input.instruction, p_sources: sources,
    p_expires_at: new Date(Date.now() + input.minutes * 60_000).toISOString(), p_key: input.key,
  });
  if (error?.message?.includes("intelligence not approved")) throw new Error("intelligence_not_approved");
  if (error?.message?.includes("intelligence budget exhausted")) throw new Error("intelligence_budget_exhausted");
  const id = z.uuid().safeParse(data);
  if (error || !id.success) throw new Error("task_not_created");
  return id.data;
}

const pendingRowSchema = z.object({
  id: z.uuid(), commit_sha: z.string(), host: z.enum(["codex", "claude-code", "chatgpt", "api"]),
  instruction: z.string(), expires_at: z.string(), repositories: z.object({ full_name: z.string() }),
  kind: z.enum(["review", "attack_reasoning", "attack_verification"]),
});

/** What a customer's host polls for (10B-2a): its own pending, unexpired
 * tasks, newest first. Paths and hashes come from getIntelligenceTask. */
export async function listPendingIntelligenceTasks(userId: string) {
  const { data, error } = await getSupabaseAdmin().from("intelligence_tasks")
    .select("id, commit_sha, host, instruction, expires_at, kind, repositories(full_name)")
    .eq("user_id", userId).eq("status", "pending").gt("expires_at", new Date().toISOString())
    // Tasks of the retired API-key mode are never offered to an agent.
    .neq("host", "api")
    .order("created_at", { ascending: false }).limit(20);
  if (error) throw new Error("tasks_unreadable");
  return (data ?? []).flatMap((raw) => {
    const row = pendingRowSchema.safeParse(raw);
    return row.success ? [{ taskId: row.data.id, repository: row.data.repositories.full_name, commit: row.data.commit_sha,
      host: row.data.host, kind: row.data.kind, instruction: row.data.instruction, expiresAt: row.data.expires_at }] : [];
  });
}

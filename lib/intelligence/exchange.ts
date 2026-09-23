import { createHash } from "node:crypto";
import { z } from "zod";

// 10B-0: in-memory protocol proof. No credentials, network, database, file
// writes, inference, or PR authority. Production needs authenticated durable
// admission (10B-1); echoing these IDs is not authentication.
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const identitySchema = z.object({
  taskId: z.string().uuid(), tenantId: z.string().uuid(), repositoryId: z.string().uuid(),
  commit: z.string().regex(/^[a-f0-9]{40}$/), connectionEpoch: hash,
  attempt: z.number().int().min(1).max(100),
}).strict();
const hostSchema = z.enum(["codex", "claude-code", "chatgpt", "api"]);
const pathSchema = z.string().min(1).max(240).refine((path) =>
  !path.startsWith("/") && !path.includes("\\") &&
  !path.split("/").some((part) => part === ".." || part === "." || part === "") &&
  !/[\x00-\x1f\x7f]/.test(path));

export const intelligenceResultSchema = z.object({
  version: z.literal(1), identity: identitySchema, host: hostSchema,
  model: z.string().min(1).max(100),
  status: z.enum(["proposed", "needs_human", "unavailable"]),
  reason: z.enum(["host_offline", "quota_exhausted", "unsupported", "cancelled"]).optional(),
  summary: z.string().min(1).max(2_000),
  citations: z.array(z.object({
    path: pathSchema, sourceHash: hash,
    startLine: z.number().int().min(1), endLine: z.number().int().min(1),
    quote: z.string().min(1).max(8_000),
  }).strict()).max(16),
  edits: z.array(z.object({ path: pathSchema, baseHash: hash,
    content: z.string().min(1).max(32_000) }).strict()).max(3),
  // Self-reported telemetry, never authority to debit tokens or claim zero cost.
  usage: z.object({ inputTokens: z.number().int().min(0).max(10_000_000),
    outputTokens: z.number().int().min(0).max(10_000_000) }).strict().nullable(),
}).strict();

export type IntelligenceIdentity = z.infer<typeof identitySchema>;
export type IntelligenceHost = z.infer<typeof hostSchema>;
export type SourceFile = { path: string; content: string };
type Result = z.infer<typeof intelligenceResultSchema>;
type Receipt = {
  taskId: string; digest: string;
  status: "proposal_received" | "needs_human" | "unavailable";
  applied: false; prOpened: false; tests: "not_run"; modelUsageVerified: false;
};

export function sourceHash(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Evidence rules shared by the in-memory proof and durable tasks (10B-1b):
 * unavailable carries a reason and nothing else; any other outcome cites exact
 * lines of listed sources; only `proposed` may carry edits, each on a cited,
 * unedited-before listed file at its current hash and allowed by a trusted
 * mechanical validator. CRLF sources compare line text without the `\r`.
 */
export function checkResultEvidence(
  result: Pick<Result, "status" | "reason" | "citations" | "edits">,
  source: (path: string) => SourceFile,
  validateEdit: (file: Readonly<SourceFile>, proposed: string) => boolean,
): void {
  if (result.status === "unavailable") {
    if (!result.reason || result.edits.length || result.citations.length) throw new Error("invalid_unavailable");
    return;
  }
  if (result.reason || !result.citations.length) throw new Error("missing_evidence");
  for (const citation of result.citations) {
    const file = source(citation.path);
    const lines = file.content.split("\n").map((line) => line.replace(/\r$/, ""));
    if (citation.sourceHash !== sourceHash(file.content) || citation.endLine < citation.startLine ||
        citation.endLine > lines.length ||
        lines.slice(citation.startLine - 1, citation.endLine).join("\n") !== citation.quote.replace(/\r\n/g, "\n")) {
      throw new Error("citation_mismatch");
    }
  }
  if (result.status === "needs_human" && result.edits.length) throw new Error("human_decision_required");
  if (result.status === "proposed" && !result.edits.length) throw new Error("missing_patch");
  const edited = new Set<string>();
  for (const edit of result.edits) {
    const file = source(edit.path);
    if (edited.has(edit.path) || edit.baseHash !== sourceHash(file.content) ||
        !result.citations.some((citation) => citation.path === edit.path) ||
        !validateEdit(file, edit.content)) throw new Error("edit_not_allowed");
    edited.add(edit.path);
  }
}

export function createIntelligenceExchange(input: {
  identity: IntelligenceIdentity; host: IntelligenceHost; instruction: string;
  files: SourceFile[]; expiresAt: number; now: () => number;
  currentIdentity: () => IntelligenceIdentity | null;
  // Supplied by ShipLock using an allowlisted mechanical transform, never by
  // the model. A parser-only check does not authorize business-policy changes.
  validateEdit: (file: Readonly<SourceFile>, proposed: string) => boolean;
}) {
  const identity = identitySchema.parse(input.identity);
  const host = hostSchema.parse(input.host);
  const identityKey = JSON.stringify(identity);
  const files = new Map<string, SourceFile>();
  let sourceBytes = 0;
  if (!input.files.length || input.files.length > 16 ||
      !Number.isFinite(input.expiresAt) || input.expiresAt <= input.now() ||
      input.expiresAt - input.now() > 15 * 60_000 || input.instruction.length > 2_000) {
    throw new Error("invalid_task");
  }
  for (const file of input.files) {
    pathSchema.parse(file.path);
    sourceBytes += Buffer.byteLength(file.content);
    if (files.has(file.path) || Buffer.byteLength(file.content) > 32_000 || sourceBytes > 64_000) {
      throw new Error("invalid_source_budget");
    }
    files.set(file.path, Object.freeze({ ...file }));
  }
  const instruction = input.instruction;
  const expiresAt = input.expiresAt;
  let calls = 0;
  let accepted: Result | null = null;
  let receipt: Receipt | null = null;

  function check() {
    if (input.now() >= expiresAt) throw new Error("task_expired");
    const current = identitySchema.safeParse(input.currentIdentity());
    if (!current.success || JSON.stringify(current.data) !== identityKey) throw new Error("task_scope_changed");
    if (++calls > 24) throw new Error("call_budget_exhausted");
  }
  function source(path: string) {
    const file = files.get(path);
    if (!file) throw new Error("source_not_allowed");
    return file;
  }

  return {
    getTask() {
      check();
      return { version: 1, identity: structuredClone(identity), host, instruction,
        funding: "customer", permission: "propose_only", status: receipt?.status ?? "pending",
        expiresAt, limits: { calls: 24, sourceBytes: 64_000, resultBytes: 64_000, edits: 3 },
        sources: [...files.values()].map((file) => ({ path: file.path, sourceHash: sourceHash(file.content) })),
        resultSchema: z.toJSONSchema(intelligenceResultSchema),
      };
    },
    readSource(path: string) {
      check();
      const file = source(path);
      return { ...file, sourceHash: sourceHash(file.content) };
    },
    submit(raw: unknown): Receipt {
      check();
      let bytes: string | undefined;
      try { bytes = JSON.stringify(raw); } catch { throw new Error("invalid_result"); }
      if (bytes && Buffer.byteLength(bytes) > 64_000) throw new Error("result_too_large");
      const parsed = intelligenceResultSchema.safeParse(raw);
      if (!parsed.success) throw new Error("invalid_result");
      const result = parsed.data;
      if (JSON.stringify(result.identity) !== identityKey || result.host !== host) throw new Error("scope_mismatch");
      const digest = sourceHash(JSON.stringify(result));
      if (receipt) {
        if (receipt.digest !== digest) throw new Error("already_completed");
        return structuredClone(receipt);
      }
      checkResultEvidence(result, source, input.validateEdit);
      receipt = { taskId: identity.taskId, digest,
        status: result.status === "proposed" ? "proposal_received" : result.status,
        applied: false, prOpened: false, tests: "not_run", modelUsageVerified: false };
      accepted = structuredClone(result);
      return structuredClone(receipt);
    },
    getResult() {
      check();
      return receipt ? { receipt: structuredClone(receipt),
        outcome: accepted ? { status: accepted.status, reason: accepted.reason,
          summary: accepted.summary } : null,
        proposal: accepted?.status === "proposed" ? structuredClone(accepted) : null }
        : { status: "pending" as const };
    },
  };
}

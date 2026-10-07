import { guardHypotheses, safeConsequence, type AttackClass, type Hypothesis } from "@/lib/agent/attackGuard";
import { buildFindings, type AgentFinding } from "@/lib/agent/findings";
import { applyVerdicts, checkVerdicts, type RawVerdict, type VerifyItem } from "@/lib/agent/verify";
import { taskBrief, verificationBatches, type ReasoningContext, type ReasoningTask } from "@/lib/intelligence/reasoning";

/**
 * The customer agent's path, offline (plan item H, option B; Felipe
 * 2026-10-06: measure the whole harness, not only the code-only checks).
 * Each step calls production's own function from
 * lib/intelligence/reasoning.ts: the reasoning brief, the guard, the
 * verification batches and brief, and the admission of quoted proof. Only
 * the transport differs: files stand in for Supabase tasks and for reading
 * the source from GitHub, so a measurement here is a measurement of what a
 * founder would be shown.
 */
const brief = (kind: string, context: unknown) => taskBrief({ kind, context } as unknown as ReasoningTask);

/** What the agent reads for an audit's reasoning task. */
export function reasoningBrief(context: ReasoningContext) {
  return brief("attack_reasoning", context);
}

/** The agent's hypotheses, judged as submitReasoningResult judges them. */
export function guardAnswer(context: ReasoningContext, hypotheses: unknown) {
  return guardHypotheses(hypotheses, {
    entries: new Set(context.routes.map((r) => r.path)), files: new Set(context.files), tables: new Set(context.tables),
    facts: new Set(context.liveFacts.map((f) => f.id)), routes: new Map(context.routes.map((r) => [r.path, r])),
    possessionGates: new Map(context.possessionGates),
  });
}

export type VerificationTask = {
  index: number; hypotheses: (Hypothesis & { attackClass: AttackClass })[]; items: VerifyItem[];
  sources: { path: string; content: string }[]; brief: ReturnType<typeof brief>;
};

/** Verification tasks for what the guard admitted, batched and briefed as production does. */
export function verificationTasks(context: ReasoningContext, admitted: (Hypothesis & { attackClass: AttackClass })[],
  contentOf: (path: string) => string | null): VerificationTask[] {
  const tasks: VerificationTask[] = [];
  for (const [index, batch] of verificationBatches(admitted, context.routes).entries()) {
    const sources = batch.files.map((path) => ({ path, content: contentOf(path) }))
      .filter((s): s is { path: string; content: string } => s.content !== null);
    if (sources.length === 0) continue;
    const items = batch.hypotheses.map((h, i): VerifyItem => ({ id: String(i), entry: h.entry, attackClass: h.attackClass,
      title: h.title, consequence: h.consequence, citedFiles: h.citedFiles ?? [],
      handlerFile: context.routes.find((r) => r.path === h.entry)?.file }));
    tasks.push({ index, hypotheses: batch.hypotheses, items, sources,
      brief: brief("attack_verification", { version: 1, hypotheses: batch.hypotheses, items }) });
  }
  return tasks;
}

/** The agent's verdicts, admitted as submitVerificationResult admits them. */
export function admitVerified(context: ReasoningContext, task: Pick<VerificationTask, "hypotheses" | "items" | "sources">,
  raw: unknown[], repositoryId: string): { findings: AgentFinding[]; confirmed: number; refuted: number; unverified: number } {
  const files = new Map(task.sources.map((s) => [s.path, s.content]));
  const verdicts = checkVerdicts(raw as RawVerdict[], task.items, files, new Set(files.keys()));
  const applied = applyVerdicts(task.hypotheses, verdicts.map((v) => (safeConsequence(v.statement.trim()) ? v : { ...v, statement: "" })));
  const findings = buildFindings({
    admitted: applied.kept, deterministic: [], routes: context.routes, stack: context.stack, repositoryId,
    hasDatabase: context.hasDatabase, liveFacts: context.liveFacts, possessionGates: new Map(context.possessionGates),
    oneIdAccess: new Map(context.oneIdAccess),
  }).filter((f) => f.attackClass !== "permission_gap" && f.attackClass !== "committed_secret");
  return { findings, confirmed: applied.kept.length, refuted: applied.refuted, unverified: applied.unverified };
}

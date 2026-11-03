import Anthropic from "@anthropic-ai/sdk";
import { buildPrompt, judgeAnswer, MAX_PROMPT_ROUTES, nothingToAsk, SYSTEM, type AgentInput, type AgentOutcome } from "../lib/agent/attack";
import { buildVerifyPrompt, checkVerdicts, parseVerdicts, selectVerifyContext, VERIFY_SCHEMA, VERIFY_SYSTEM, type Verdict, type VerifyItem } from "../lib/agent/verify";

// DEVELOPER TOOL ONLY. ShipLock the product makes no model call (Felipe,
// 2026-10-01; lib/security/modelFunding.test.ts). These are the model calls
// of the offline corpus harness (scripts/corpus.cjs paid and verify), which
// Felipe runs on his own key with --confirm-paid and a dollar cap. The prompt
// and the reading of each answer are the product's own (lib/agent/attack.ts,
// lib/agent/verify.ts), so a measurement here measures what the customer's
// agent is asked and how its answer is judged.

/** Felipe's rule: a top-tier model, never a small one. Opus 5.5 always thinks
 * and its thinking counts toward max_tokens, so the answer budget gets
 * THINKING_HEADROOM on top. It rejects sampling parameters: none are sent. */
export const PROPOSE_MODEL = "claude-opus-5-5";
export const THINKING_HEADROOM = 16_000;

// Benchmark overrides and the request each needs: Sonnet 5 rejects sampling
// parameters and thinks by default, which would spend the output budget.
const TEST_MODELS: Record<string, { thinking: { type: "disabled" } }> = {
  "claude-sonnet-5": { thinking: { type: "disabled" } },
};

/** Output budget sized to the answer asked for: about 220 tokens a finding,
 * over at most MAX_PROMPT_ROUTES routes. A flat 2000 once overflowed on every
 * real codebase and the overflow read as a clean report. */
export function maxTokensFor(interestingEntries: number): number {
  const askedAbout = Math.min(interestingEntries, MAX_PROMPT_ROUTES);
  return Math.min(16000, Math.max(4000, Math.ceil(askedAbout * 220)));
}

type Usage = { model: string; input_tokens: number; output_tokens: number; cache_read_input_tokens: number | null; stopReason: string | null };
type CorpusOutcome = AgentOutcome & { usage?: Usage };

/** One proposing call over a pinned repository's recon. Fails into a stated
 * skip, never into an empty answer that reads as clean. */
export async function proposeAttacks(input: AgentInput & { model?: string; timeoutMs?: number }): Promise<CorpusOutcome> {
  const empty = nothingToAsk(input);
  if (empty) return empty;
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { admitted: [], rejected: [], unassessed: [], unmatchedEntries: [], model: "none", skipped: true, skipReason: "no model credential configured" };
  if (input.model !== undefined && !TEST_MODELS[input.model]) throw new Error(`${input.model} is not an allowed test model`);
  const model = input.model ?? PROPOSE_MODEL;
  const interesting = input.routes.filter((r) => r.tables.length > 0).length;
  try {
    const response = await new Anthropic({ apiKey }).messages.create({
      model,
      max_tokens: maxTokensFor(interesting) + (input.model ? 0 : THINKING_HEADROOM),
      ...(input.model ? TEST_MODELS[input.model] : { output_config: { effort: "medium" as const } }),
      system: SYSTEM,
      messages: [{ role: "user", content: buildPrompt(input) }],
    }, input.timeoutMs ? { timeout: input.timeoutMs } : undefined);
    const usage = { model, input_tokens: response.usage.input_tokens, output_tokens: response.usage.output_tokens,
      cache_read_input_tokens: response.usage.cache_read_input_tokens ?? null, stopReason: response.stop_reason ?? null };
    const text = response.content.map((block) => (block.type === "text" ? block.text : "")).join("");
    return { ...judgeAnswer(input, text, response.stop_reason ?? null, model), usage };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    const timedOut = err instanceof Anthropic.APIConnectionTimeoutError || /timeout/i.test(message);
    return { admitted: [], rejected: [], unassessed: [], unmatchedEntries: [], model, skipped: true,
      skipReason: timedOut ? "reasoning did not finish inside this run's time budget" : `model call failed: ${message}` };
  }
}

/** The skeptical verifier model. A 5.5-generation model, never a small one. */
export const VERIFY_MODEL = "claude-sonnet-5-5";
const VERIFY_MAX_TOKENS = 16_000;
/** Claims per verifier call, so each verdict keeps room to cite its lines. */
export const VERIFY_BATCH = 10;

interface VerifyOutcome {
  verdicts: Verdict[]; shown: string[]; omitted: string[]; model: string; skipped: boolean; skipReason?: string; usage?: Usage;
}

/** Second pass over admitted hypotheses (lib/agent/verify.ts). A failure
 * verifies nothing: every claim is then unverified. */
export async function verifyAttacks(input: { items: VerifyItem[]; files: ReadonlyMap<string, string>; timeoutMs?: number; model?: string;
  maxTokens?: number; budgetChars?: number }): Promise<VerifyOutcome> {
  const context = selectVerifyContext(input.items, input.files, input.budgetChars);
  const unverifiedAll = (reason: string): Verdict[] => input.items.map((item) =>
    ({ id: item.id, verdict: "unverified", severity: "medium", statement: "", reason, citations: [], citationProblem: "not run" }));
  const model = input.model ?? VERIFY_MODEL;
  if (input.items.length === 0) return { verdicts: [], ...context, model: "none", skipped: true, skipReason: "nothing to verify" };
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { verdicts: unverifiedAll("no model credential configured"), ...context, model: "none", skipped: true, skipReason: "no model credential configured" };
  try {
    const response = await new Anthropic({ apiKey, maxRetries: 0 }).messages.create({
      model,
      max_tokens: input.maxTokens ?? VERIFY_MAX_TOKENS,
      output_config: { effort: "high", format: { type: "json_schema", schema: VERIFY_SCHEMA as unknown as Record<string, unknown> } },
      system: VERIFY_SYSTEM,
      messages: [{ role: "user", content: buildVerifyPrompt(input.items, input.files, context) }],
    }, input.timeoutMs ? { timeout: input.timeoutMs } : undefined);
    const usage = { model, input_tokens: response.usage.input_tokens, output_tokens: response.usage.output_tokens,
      cache_read_input_tokens: response.usage.cache_read_input_tokens ?? null, stopReason: response.stop_reason ?? null };
    const text = response.content.map((block) => (block.type === "text" ? block.text : "")).join("");
    const raw = response.stop_reason === "refusal" ? null : parseVerdicts(text);
    if (!raw) return { verdicts: unverifiedAll("the verifier's answer could not be read"), ...context, model, skipped: false, usage };
    return { verdicts: checkVerdicts(raw, input.items, input.files, new Set(context.shown)), ...context, model, skipped: false, usage };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    return { verdicts: unverifiedAll(`verification call failed: ${message}`), ...context, model, skipped: true, skipReason: message };
  }
}

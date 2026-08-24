import Anthropic from "@anthropic-ai/sdk";
import type { AttackPath } from "./attackPaths";
import { checkNarrative, type NarrativeProposal } from "./narrativeGuard";

// Human-readable explanations for correlated findings.
//
// The model's ONLY job here is wording. It receives a path the deterministic
// reasoner already produced — already severity-ranked, already required to span
// two collectors — and returns prose. It cannot create a finding, change a
// severity, or add a fact; narrativeGuard.ts rejects anything that tries, and a
// rejection falls back to the template attackPaths.ts already wrote.
//
// Two cost decisions, both from the model in BUILD-PLAN-V1.md §3:
//
//  - ONE call per pass, not one per path. Prompt caching does not help here the
//    way it first appears to: the cache TTL is an hour and passes are 48 hours
//    apart, so a customer's context never survives to the next call. Batching is
//    the lever that actually works, and it sidesteps the TTL mismatch instead of
//    fighting it.
//  - Called only when the diff engine reports a genuinely NEW correlated
//    finding. Routine passes stay at zero tokens, which preserves the guarantee
//    in CLAUDE.md that monitoring never calls Claude — that rule exists because
//    a scheduled background poll running thousands of times should not carry
//    per-run AI cost, and a narrative for a finding the customer already read is
//    exactly the kind of spend that buys nothing.

const MODEL = "claude-haiku-4-5-20251001";
const TIMEOUT_MS = 20_000;
const MAX_PATHS_PER_CALL = 6;

// Under CLAUDE.md's 300-token system-prompt budget. The constraints are stated
// as rules rather than examples on purpose: examples are the expensive way to
// convey a format, and the guard enforces the rules anyway.
const SYSTEM_PROMPT = `You explain security findings to a busy technical founder.

For each finding you receive, write one short paragraph (max 3 sentences) saying why it matters, using ONLY the facts given.

Rules:
- Use only the supplied facts. Never add a fact, number, or detail.
- Never claim a breach happened, data was accessed, or anyone was affected. These findings describe what is reachable, not what occurred.
- Only mention observed traffic if a fact came from the traffic collector.
- Plain language. No CVSS, no grades, no jargon the reader must look up.
- The reader is technical and busy: say what is true and what it costs them, not what a scanner does.

Return JSON only: {"narratives":[{"id":"<finding id>","narrative":"<text>","citedFacts":["<exact fact string>"]}]}
citedFacts must quote the supplied facts exactly.`;

export interface NarrativeResult {
  /** Path id -> accepted narrative. Paths absent here keep their template. */
  accepted: Map<string, string>;
  /** Rejections, for logging. A rejected narrative is never shown. */
  rejected: { id: string; reason: string }[];
  tokensIn: number;
  tokensOut: number;
}

const EMPTY: NarrativeResult = {
  accepted: new Map(),
  rejected: [],
  tokensIn: 0,
  tokensOut: 0,
};

function buildUserPrompt(paths: AttackPath[]): string {
  return paths
    .map((p) =>
      [
        `id: ${p.id}`,
        `title: ${p.title}`,
        `severity: ${p.severity}`,
        "facts:",
        ...p.evidence.map((e) => `  - [${e.collector}] ${e.fact}`),
      ].join("\n")
    )
    .join("\n\n");
}

function parseProposals(raw: string): { id: string; proposal: NarrativeProposal }[] {
  // The model is asked for JSON only, but a stray prose wrapper is the classic
  // failure and is cheap to tolerate — extract the outermost object rather than
  // discarding a whole batch over a preamble.
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start === -1 || end <= start) return [];

  let parsed: { narratives?: { id?: string; narrative?: string; citedFacts?: string[] }[] };
  try {
    parsed = JSON.parse(raw.slice(start, end + 1));
  } catch {
    return [];
  }

  return (parsed.narratives ?? [])
    .filter((n): n is { id: string; narrative: string; citedFacts?: string[] } =>
      Boolean(n.id && n.narrative)
    )
    .map((n) => ({
      id: n.id,
      proposal: { narrative: n.narrative, citedFacts: n.citedFacts ?? [] },
    }));
}

/**
 * Generate narratives for newly-found correlated paths.
 *
 * Fails into silence, never into a wrong answer: any API error, timeout, or
 * unparseable response returns an empty result and every path keeps the
 * deterministic wording it already had. The customer never sees a blank finding
 * because of this call, and never waits on it either — the findings are already
 * written by the time this runs.
 */
export async function generateNarratives(paths: AttackPath[]): Promise<NarrativeResult> {
  if (paths.length === 0) return EMPTY;
  if (!process.env.ANTHROPIC_API_KEY) return EMPTY;

  // Bounded per call. More than a handful of new correlated paths in one pass is
  // itself unusual, and a runaway prompt is the one cost failure mode that does
  // not announce itself.
  const batch = paths.slice(0, MAX_PATHS_PER_CALL);

  let raw: string;
  let tokensIn = 0;
  let tokensOut = 0;
  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY, timeout: TIMEOUT_MS });
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 1_200,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: buildUserPrompt(batch) }],
    });
    tokensIn = response.usage.input_tokens;
    tokensOut = response.usage.output_tokens;
    raw = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
  } catch (err) {
    console.error(
      "[graph/narrative] generation failed, keeping template wording:",
      err instanceof Error ? err.message : err
    );
    return EMPTY;
  }

  // Haiku pricing, per the token-efficiency doctrine's logging requirement.
  const cost = (tokensIn / 1_000_000) * 1 + (tokensOut / 1_000_000) * 5;
  console.log(
    `[TOKENS] model=${MODEL} input=${tokensIn} output=${tokensOut} cost=$${cost.toFixed(5)}`
  );

  const byId = new Map(batch.map((p) => [p.id, p]));
  const accepted = new Map<string, string>();
  const rejected: { id: string; reason: string }[] = [];

  for (const { id, proposal } of parseProposals(raw)) {
    const path = byId.get(id);
    if (!path) {
      // An id we never sent. Not necessarily malice — but it describes nothing
      // we can check, so it cannot be shown.
      rejected.push({ id, reason: "narrative for an unknown finding id" });
      continue;
    }
    const verdict = checkNarrative(proposal, path);
    if (verdict.allowed) {
      accepted.set(id, proposal.narrative.trim());
    } else {
      rejected.push({ id, reason: verdict.reason });
    }
  }

  if (rejected.length > 0) {
    console.warn(
      `[graph/narrative] ${rejected.length} narrative(s) rejected by the guard:`,
      rejected.map((r) => `${r.id}: ${r.reason}`).join("; ")
    );
  }

  return { accepted, rejected, tokensIn, tokensOut };
}

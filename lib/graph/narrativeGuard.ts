import type { AttackPath } from "./attackPaths";

// The guard for correlation narratives.
//
// Same split as lib/proving/agentGuard.ts, applied to prose instead of SQL: the
// model proposes wording, deterministic code decides whether it may be shown.
// The model never gets to close its own loop.
//
// The threat here is not a malicious model. It is a capable one being helpful in
// an unwanted direction — inventing a corroborating detail that reads well and
// was never collected, or escalating "traffic corroborates this path" into
// "you have been breached". Both are plausible completions and both are lies we
// would be putting our name on, in the one place a customer is deciding whether
// to trust us enough to let us touch their database.
//
// So: every fact the narrative cites must be one we handed it, and no narrative
// may assert something the evidence cannot license. A rejected narrative falls
// back to the deterministic template that already exists, never to a blank
// state — same fail-closed posture as the rest of lib/proving.

export interface NarrativeProposal {
  narrative: string;
  citedFacts: string[];
}

export type NarrativeVerdict =
  | { allowed: true }
  | { allowed: false; reason: string };

/** Longer than this is not a summary, and is not what was asked for. */
const MAX_NARRATIVE_LENGTH = 700;

/**
 * Claims the evidence can never license.
 *
 * Traffic facts are corroboration, never proof: lib/traffic/graphFacts.ts builds
 * them only from sources ALREADY judged suspicious, and a hot path means someone
 * knocked, not that they got in. attackPaths.ts is careful about this in its own
 * templates ("under active attention"), and a narrative must not quietly upgrade
 * it. Likewise, nothing in the graph observes exfiltration — the graph reasons
 * about reachability, so any past-tense breach claim is fabricated by
 * construction.
 */
const UNLICENSED_CLAIMS: { pattern: RegExp; reason: string }[] = [
  {
    pattern: /\b(has|have|was|were|been)\s+(breached|exfiltrated|stolen|compromised|leaked)\b/i,
    reason: "asserts a past breach; the graph observes reachability, never exfiltration",
  },
  {
    pattern: /\bactively\s+(being\s+)?(exploited|attacked|breached)\b/i,
    reason: "asserts active exploitation; traffic facts show knocking, not entry",
  },
  {
    pattern: /\b(confirmed|proven|verified)\s+(breach|exploit|compromise|data\s+loss)\b/i,
    reason: "claims proof of compromise, which no collector can establish",
  },
  {
    pattern: /\b(your|user)\s+data\s+(has|have|was|were)\s+(been\s+)?(accessed|taken|downloaded)\b/i,
    reason: "asserts data was accessed; ShipLock never reads customer data",
  },
  {
    pattern: /\b\d+\s+(users?|records?|rows?)\s+(affected|exposed|leaked|breached)\b/i,
    reason: "quantifies impact; no collector counts affected records",
  },
];

/**
 * Judge a proposed narrative against the path it claims to describe.
 *
 * Deliberately strict and deliberately dumb: this must be readable in one pass
 * by someone deciding whether to trust it, which rules out anything model-based
 * or heuristic. Every rule below is a flat check against data we already have.
 */
export function checkNarrative(
  proposal: NarrativeProposal,
  path: AttackPath
): NarrativeVerdict {
  const narrative = (proposal.narrative ?? "").trim();

  if (narrative.length === 0) {
    return { allowed: false, reason: "empty narrative" };
  }
  if (narrative.length > MAX_NARRATIVE_LENGTH) {
    return {
      allowed: false,
      reason: `narrative is ${narrative.length} chars, over the ${MAX_NARRATIVE_LENGTH} limit`,
    };
  }

  // Every cited fact must be one we supplied. This is the prose equivalent of
  // agentGuard's "every FROM/JOIN target must be inside the replica schema": the
  // model may reorganise what it was given and may not introduce anything else.
  const supplied = new Set(path.evidence.map((e) => e.fact));
  for (const cited of proposal.citedFacts ?? []) {
    if (!supplied.has(cited)) {
      return { allowed: false, reason: `cites a fact that was never collected: ${cited}` };
    }
  }

  // A narrative citing nothing is not grounded in the path it describes.
  if (!proposal.citedFacts || proposal.citedFacts.length === 0) {
    return { allowed: false, reason: "cites no facts" };
  }

  for (const { pattern, reason } of UNLICENSED_CLAIMS) {
    if (pattern.test(narrative)) {
      return { allowed: false, reason };
    }
  }

  // Traffic language is only licensed when traffic actually contributed. A path
  // spanning code and database says nothing about whether anyone is knocking.
  //
  // Matching the bare word "request" here was the first attempt and was wrong:
  // "nothing between the request and the table checks who is asking" is ordinary
  // prose describing a route, not a claim about observed traffic, and rejecting
  // it would have pushed the model toward vaguer wording to get past the guard.
  // What must be licensed is an OBSERVATIONAL claim — that we are seeing
  // something — so the pattern requires an observation verb, not a noun.
  const hasTrafficEvidence = path.evidence.some((e) => e.collector === "traffic");
  const OBSERVED_TRAFFIC =
    /\b(seeing|observed|detected|receiving|recorded|flagged|logged)\b[^.]{0,40}\b(traffic|requests?|attempts?|probes?|scanning)\b|\b(attackers?|bots?)\s+(are|is|have|has)\b|\bunder\s+(attack|active\s+attention)\b|\bbeing\s+(probed|scanned|targeted)\b/i;
  if (!hasTrafficEvidence && OBSERVED_TRAFFIC.test(narrative)) {
    return {
      allowed: false,
      reason: "claims observed traffic, but no traffic collector contributed to this path",
    };
  }

  return { allowed: true };
}

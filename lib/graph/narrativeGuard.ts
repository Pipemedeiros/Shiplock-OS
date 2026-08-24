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
/**
 * Words that assert a compromise actually happened.
 *
 * Matched independently of tense, because the first version of this list keyed
 * on past-tense auxiliaries ("has been breached") and every present-tense
 * phrasing walked straight through it — "your database is breached right now",
 * "this table is compromised", "attackers are exfiltrating your orders" all
 * passed a guard whose entire purpose was to stop exactly those sentences. The
 * lesson generalises: enumerate the CLAIM, not the grammar someone might use to
 * make it.
 */
// Words that can only describe a compromise that ALREADY HAPPENED. There is no
// reading of "exfiltrated" or "compromised" that describes mere reachability, so
// these are refused wherever they appear as a verb about the customer's system.
// `exploit`/`attack` require an inflection on purpose: "this is exploitable" and
// "attack path" are the product's own vocabulary for describing what is
// POSSIBLE, and must stay sayable. Only "exploited"/"exploiting"/"attacked"
// assert it happened.
const COMPROMISE_WORD = String.raw`breach(?:ed|es|ing)?|exfiltrat(?:ed|es|ing|ion)|stolen|steal(?:ing|s)?|compromis(?:ed|es|ing)|dump(?:ed|ing)|harvest(?:ed|ing)|scrap(?:ed|ing)|exploit(?:ed|ing)|attack(?:ed|ing)`;

// Words that are AMBIGUOUS and must not be blanket-banned: "your records can be
// read by anyone" is an accurate description of reachability. These are refused
// only in an event frame ("is being downloaded"), never in a capability frame
// ("can be downloaded"). Inflections are listed because "Hackers are reading
// your records" is an event claim and "read" alone does not catch it.
//
// "exposed" is deliberately NOT here. It describes a STATE, not an action —
// "your service-role key is exposed in the bundle you ship" is both accurate and
// something bundleAudit genuinely proves by downloading the file. Treating it as
// an event claim rejected the single most valuable sentence the product writes.
const REACH_WORD = String.raw`access(?:ed|ing)|tak(?:en|ing)|download(?:ed|ing)|read(?:ing)?|leak(?:ed|ing)`;

/** Auxiliaries and adverbs that assert something is happening or has happened. */
const ASSERTION_LEAD = String.raw`is|are|was|were|has|have|had|been|being|already|currently|now|actively`;

/**
 * Capability framing — "can", "could", "anyone who", "would be able to".
 *
 * Its presence anywhere in the sentence means the claim is about what is
 * POSSIBLE, which is exactly what the graph reasons about and must stay sayable.
 * Without this carve-out the guard rejects the most useful sentence the product
 * can write, and a guard that blocks honest wording just teaches the model to be
 * vague.
 */
const CAPABILITY_FRAME = /\b(can|could|would|may|might|able to|anyone who|if someone)\b/i;

const UNLICENSED_CLAIMS: { pattern: RegExp; reason: string }[] = [
  {
    // "has been breached", "is breached", "are being exfiltrated" — and, unlike
    // the first version of this rule, also the bare present tense that walked
    // straight through it.
    pattern: new RegExp(
      String.raw`\b(?:${ASSERTION_LEAD})\b(?:\s+\w+){0,3}\s+\b(?:${COMPROMISE_WORD})\b|\b(?:${COMPROMISE_WORD})\b`,
      "i"
    ),
    reason:
      "asserts a compromise occurred; the graph observes reachability, never exfiltration",
  },
  {
    // "attackers are downloading your data" — an actor performing the action
    // makes even an ambiguous word an event claim.
    pattern: new RegExp(
      String.raw`\b(?:attackers?|hackers?|someone|somebody|intruders?)\b(?:\s+\w+){0,3}\s+\b(?:${REACH_WORD}|${COMPROMISE_WORD})\b`,
      "i"
    ),
    reason: "names an actor performing the action, which no collector observes",
  },
  {
    pattern: /\b(confirmed|proven|verified)\s+(breach|exploit|compromise|data\s+loss)\b/i,
    reason: "claims proof of compromise, which no collector can establish",
  },
  {
    pattern: /\b\d+\s+(users?|records?|rows?|customers?)\s+(affected|exposed|leaked|breached|impacted)\b/i,
    reason: "quantifies impact; no collector counts affected records",
  },
];

/**
 * Event-framed use of an ambiguous word, e.g. "is being downloaded".
 *
 * Separate from the list above because it is the one rule that must yield to a
 * capability frame — checked in checkNarrative rather than inlined, so the
 * exception is visible rather than buried in a lookahead.
 */
const EVENT_FRAMED_REACH = new RegExp(
  String.raw`\b(?:${ASSERTION_LEAD})\b(?:\s+\w+){0,2}\s+\b(?:${REACH_WORD})\b`,
  "i"
);

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

  // Ambiguous verbs are refused only when framed as something happening, and
  // allowed when framed as something possible — "is being downloaded" is a claim
  // we cannot support, "can be downloaded by anyone" is the finding itself.
  if (EVENT_FRAMED_REACH.test(narrative) && !CAPABILITY_FRAME.test(narrative)) {
    return {
      allowed: false,
      reason: "asserts data was reached; the graph shows what is possible, not what occurred",
    };
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

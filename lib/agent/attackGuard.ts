/**
 * The deterministic half of the repository agent.
 *
 * The model proposes attack hypotheses; this file disposes of them. That split
 * is the same one enforced in lib/proving/agentGuard.ts and
 * lib/graph/narrativeGuard.ts, and it is the reason an LLM can be pointed at a
 * customer's codebase at all: nothing the model emits is trusted as a fact, a
 * location, or a permission.
 *
 * Strix validates a hypothesis by exploiting it. We cannot -- the target is a
 * customer's production application, and attacking it is permanently out of
 * bounds. So the burden shifts: a hypothesis is admitted only when every
 * concrete thing it asserts can be checked against the recon we performed
 * ourselves. The model may reason about what an attacker would try; it may not
 * invent a route, a file, a table, or a vulnerability class.
 *
 * SAFETY-CRITICAL. Loosening a rule here means shipping a model's imagination to
 * a customer as a security finding.
 */

/** The classes we are prepared to report. A hypothesis outside this is refused. */
export const ATTACK_CLASSES = [
  "missing_authorization",
  "missing_authentication",
  "unsigned_webhook",
  "secret_exposure",
  "server_boundary_crossed",
  "injection",
  "unsafe_redirect",
  "mass_assignment",
] as const;

export type AttackClass = (typeof ATTACK_CLASSES)[number];

export interface Hypothesis {
  entry: string;
  attackClass: string;
  title: string;
  consequence: string;
  /** Files the model says support this. Every one must exist. */
  citedFiles: string[];
  /** Tables the model says are reachable. Every one must be in the inventory. */
  citedTables?: string[];
  /**
   * Live provider facts the model says support this, by stable id.
   *
   * A fact read from a provider's API has no file to cite: "sign-up is open" or
   * "this variable exists in production" lives in someone else's system. This
   * field is how such a claim gets a location, and every id is checked against
   * the facts WE collected this run, exactly as files and tables are.
   */
  citedFacts?: string[];
}

/** What the agent is allowed to reason about -- collected by us, not the model. */
export interface ReconIndex {
  entries: Set<string>;
  files: Set<string>;
  tables: Set<string>;
  /**
   * Stable ids of live provider facts observed THIS RUN.
   *
   * Optional so every existing caller keeps working, and absent means the model
   * may cite no facts at all rather than that it may cite any.
   */
  facts?: Set<string>;
}

export type GuardVerdict =
  | { allowed: true; attackClass: AttackClass }
  | { allowed: false; reason: string };

const MAX_TITLE = 160;
const MAX_CONSEQUENCE = 400;

/** Markup or control characters, which must never reach a renderer or a PR body. */
const UNSAFE_PROSE = /[<>\u0000-\u001F]/;

/**
 * Judges one hypothesis.
 *
 * Every rejection reason names the rule, because a guard whose refusals cannot
 * be read is a guard nobody can audit.
 */
export function judgeHypothesis(h: Hypothesis, recon: ReconIndex): GuardVerdict {
  if (!h || typeof h !== "object") return { allowed: false, reason: "not an object" };

  // 1 -- the class must be one we can describe and remediate.
  if (!ATTACK_CLASSES.includes(h.attackClass as AttackClass)) {
    return { allowed: false, reason: `unknown attack class "${h.attackClass}"` };
  }

  // 2 -- the entry point must be something WE inventoried. A model that invents
  //      a route produces a finding pointing at code that does not exist.
  //
  //      A live provider fact is also a valid entry, because a whole class of
  //      real finding has no route at all: a credential the host ships to the
  //      browser, a bucket left public, a webhook endpoint that verifies no
  //      signature. Refusing those meant the agent could read live facts and
  //      then had nowhere to hang the finding, which is how a correct
  //      observation was thrown away in testing.
  //
  //      The invariant is untouched: the entry is still required to be
  //      something we observed this run, never something the model supplied.
  const knownEntry =
    Boolean(h.entry) && (recon.entries.has(h.entry) || (recon.facts?.has(h.entry) ?? false));
  if (!knownEntry) {
    return { allowed: false, reason: `entry "${h.entry}" is not in the route inventory` };
  }

  // 3 -- a claim with no location is an opinion. A location is a file we read
  //      or a live fact we collected: a provider's configuration has no file,
  //      and refusing it outright would mean the reasoning layer can never use
  //      the half of the system that does not live in the repository.
  //
  //      The invariant is unchanged. Every citation is still checked against
  //      what WE observed, and nothing the model emits becomes a fact, a
  //      location, or a permission on its own.
  const citedFiles = Array.isArray(h.citedFiles) ? h.citedFiles : [];
  const citedFacts = Array.isArray(h.citedFacts) ? h.citedFacts : [];

  if (citedFiles.length === 0 && citedFacts.length === 0) {
    return { allowed: false, reason: "no file or live fact cited" };
  }
  for (const file of citedFiles) {
    if (typeof file !== "string" || !recon.files.has(file)) {
      return { allowed: false, reason: `cited file "${file}" was not read in this run` };
    }
  }
  for (const fact of citedFacts) {
    if (typeof fact !== "string" || !(recon.facts?.has(fact) ?? false)) {
      return { allowed: false, reason: `cited fact "${fact}" was not observed in this run` };
    }
  }

  // 4 -- tables must come from the schema we read, not from the model's guess at
  //      what a billing app probably stores.
  for (const table of h.citedTables ?? []) {
    if (typeof table !== "string" || !recon.tables.has(table)) {
      return { allowed: false, reason: `cited table "${table}" is not in the schema we read` };
    }
  }

  // 5 -- prose limits. A finding is a sentence a founder can act on, and an
  //      unbounded string from a model is a hazard in every renderer it later
  //      passes through.
  if (!h.title || h.title.length > MAX_TITLE) {
    return { allowed: false, reason: "title missing or too long" };
  }
  if (!h.consequence || h.consequence.length > MAX_CONSEQUENCE) {
    return { allowed: false, reason: "consequence missing or too long" };
  }
  if (UNSAFE_PROSE.test(h.title + h.consequence)) {
    return { allowed: false, reason: "control characters or markup in prose" };
  }

  return { allowed: true, attackClass: h.attackClass as AttackClass };
}

export interface GuardResult {
  admitted: (Hypothesis & { attackClass: AttackClass })[];
  rejected: { hypothesis: unknown; reason: string }[];
}

/**
 * Judges a batch. Rejections are RETURNED, not swallowed -- a run that discards
 * nine of ten proposals is telling us something about the prompt, and a silent
 * guard would hide it.
 */
export function guardHypotheses(raw: unknown, recon: ReconIndex): GuardResult {
  const result: GuardResult = { admitted: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { admitted: [], rejected: [{ hypothesis: raw, reason: "model did not return an array" }] };
  }

  for (const item of raw) {
    const verdict = judgeHypothesis(item as Hypothesis, recon);
    if (verdict.allowed) {
      result.admitted.push({ ...(item as Hypothesis), attackClass: verdict.attackClass });
    } else {
      result.rejected.push({ hypothesis: item, reason: verdict.reason });
    }
  }

  return result;
}

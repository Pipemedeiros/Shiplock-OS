/**
 * The deterministic half of the repository agent.
 *
 * The model proposes attack hypotheses; this file disposes of them. That split
 * is the same one enforced in lib/proving/agentGuard.ts, and it is the reason
 * a customer's agent can reason over their codebase at all: nothing it emits
 * is trusted as a fact, a location, or a permission.
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

import type { RouteFact } from "@/lib/graph/routeInventory";
import type { PossessionGate } from "./possessionGate";

/** The classes we are prepared to report. A hypothesis outside this is refused. */
const ATTACK_CLASSES = [
  "missing_authorization",
  "missing_authentication",
  "unsigned_webhook",
  "secret_exposure",
  "server_boundary_crossed",
  "injection",
  "unsafe_redirect",
  "mass_assignment",
  /**
   * Informational. The route admits whoever presents a row id and checks that
   * row against another resource the request names: access by possession,
   * described without a judgement on whether possession should be enough.
   * NEVER proposed on the model's word: admitted only where
   * lib/agent/possessionGate.ts read the gate, and otherwise refused. Not in
   * the prompt's class list, so the reasoner's input is unchanged by it.
   */
  "possession_gated",
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
   * The route facts themselves, keyed by path, for the compatibility check.
   *
   * REQUIRED, not optional. Every other field on this index answers "did we
   * observe the thing you cited"; this one answers "does what you claim about
   * it agree with what we observed". Making it optional would mean a caller
   * that forgot it silently got no checking at all, which is the exact
   * fail-open shape this whole sequence has been closing.
   */
  routes: Map<string, RouteFact>;
  /**
   * Stable ids of live provider facts observed THIS RUN.
   *
   * Optional so every existing caller keeps working, and absent means the model
   * may cite no facts at all rather than that it may cite any.
   */
  facts?: Set<string>;
  /**
   * Possession gates READ this run, keyed by route path
   * (lib/agent/possessionGate.ts).
   *
   * Optional, and absent means none: nothing is reworded and
   * `possession_gated` is refused everywhere. That is the status quo, which is
   * the safe direction -- a missing map can only leave a critical a critical.
   */
  possessionGates?: ReadonlyMap<string, PossessionGate>;
}

type GuardVerdict =
  | { allowed: true; attackClass: AttackClass; citedFacts: string[]; title?: string; consequence?: string }
  | { allowed: false; reason: string; unassessed?: string };

const MAX_TITLE = 160;
const MAX_CONSEQUENCE = 400;

/** Markup or control characters, which must never reach a renderer or a PR body. */
const UNSAFE_PROSE = /[<>\u0000-\u001F]/;
/** A consequence sentence any renderer can carry: bounded, no markup, no
 * control characters. The same rule the guard applies to hypothesis prose. */
const safeConsequence = (text: string) => text.length > 0 && text.length <= MAX_CONSEQUENCE && !UNSAFE_PROSE.test(text);

/** The verifier's wording, kept only where it is safe prose; otherwise the
 * guarded hypothesis wording stands (statement and title alike, V3). */
export function safeVerdictWording<V extends { statement: string; title?: string }>(v: V): V {
  const { title, ...rest } = v;
  const safeTitle = title !== undefined && safeConsequence(title.trim()) ? { title } : {};
  return { ...rest, statement: safeConsequence(v.statement.trim()) ? v.statement : "", ...safeTitle } as V;
}

/**
 * THE CLASS/FACT COMPATIBILITY MATRIX.
 *
 * Every other rule in this file asks whether the model cited something we
 * observed. This one asks whether what it CLAIMS about that thing agrees with
 * what we observed. Both are needed, and only the first was implemented: three
 * of seven surviving false criticals had entirely correct route facts and were
 * admitted anyway, because the prompt asked the model not to make the claim and
 * nothing refused it when it did. "Model proposes, guard disposes" was being
 * enforced for citations and merely requested for conclusions.
 *
 * Two distinct refusals, and they are not the same argument:
 *
 *   CONTRADICTED  our facts positively say otherwise. The route authenticates
 *                 and the model says it does not. This is the failure that
 *                 opened five pull requests against this codebase's own working
 *                 code, and the prompt has been rewritten twice to prevent it.
 *
 *   UNSUPPORTED   the fact the claim rests on is one we could not read. Not a
 *                 weaker version of the finding -- there is no finding, because
 *                 the assertion has nothing under it.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * class                     asserts about the route          needs readable
 * ─────────────────────────────────────────────────────────────────────────────
 * missing_authorization     an identified caller reaches     ownershipReadable
 *                           rows that are not theirs         (contradicted by
 *                                                            ownershipFiltered)
 *
 * missing_authentication    no credential of any kind is     identityReadable
 *                           required to reach this           (contradicted by
 *                                                            authenticated or
 *                                                            machineGated)
 *
 * unsigned_webhook          an inbound request is accepted   machineGateReadable
 *                           without verifying its signature  and identityReadable
 *                                                            (contradicted by
 *                                                            machineGated)
 *
 * secret_exposure           a credential is present in the   -- NOTHING --
 *                           source we read
 * server_boundary_crossed   a server-only module is          -- NOTHING --
 *                           reachable from client code
 * injection                 user input reaches an            -- NOTHING --
 *                           interpreter unsanitised
 * mass_assignment           the request body is spread       -- NOTHING --
 *                           into a write
 * possession_gated          the route admits a holder of a    a possession gate
 *                           row id, bound to another          READ on the route
 *                           resource the request names        (never inferred)
 * unsafe_redirect           a user-controlled value reaches  -- NOTHING --
 *                           a redirect target
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * THE FIVE EMPTY ROWS ARE NOT OVERSIGHTS AND MUST NOT BE FILLED IN LATER
 * WITHOUT AN ARGUMENT. Each of those claims is about the CONTENT of code we
 * read, not about who may call it. A perfectly authenticated, perfectly scoped
 * route can still concatenate user input into SQL, still spread a request body
 * into an update, still redirect wherever the query string says. Authentication
 * facts cannot contradict them, so demanding one would refuse true findings to
 * look rigorous. `secret_exposure` is the clearest case: the credential is
 * either in the file or it is not, and no property of a route bears on it.
 */
function compatibility(
  attackClass: AttackClass,
  route: RouteFact | undefined,
  gate: PossessionGate | undefined,
): { ok: true } | { ok: false; reason: string; unassessed: boolean } {
  // A description of a gate nobody read is a model's reassurance. Checked
  // before the route-less early return: this class is ABOUT a route.
  if (attackClass === "possession_gated" && (!route || !gate)) {
    return { ok: false, reason: "no possession gate was read on this route", unassessed: false };
  }
  // A hypothesis with no route -- a leaked credential citing a live fact -- has
  // no route facts to contradict. Nothing to check.
  if (!route) return { ok: true };

  switch (attackClass) {
    case "missing_authorization":
      // ownershipFiltered is route-wide ("some query here is narrowed to the
      // caller") and cannot contradict a claim about another query in the same
      // route: on planted holes this refusal dropped 6 of 9 true attacks (R1,
      // 2026-10-08). Verification with quoted lines decides those claims.
      if (!route.ownershipFiltered && !route.ownershipReadable) {
        return { ok: false, reason: `we could not read how this route narrows its query: ${route.ownershipGap}`, unassessed: true };
      }
      return { ok: true };

    case "missing_authentication":
      // R1b: `authenticated` is route-wide ("some handler resolves the
      // caller"). A method we read as never refusing an anonymous caller is
      // not contradicted by it; verification with quoted lines decides.
      if (route.machineGated || (route.authenticated && !(route.unrefusedMethods?.length))) {
        return { ok: false, reason: "we read a credential check in this route", unassessed: false };
      }
      if (!route.identityReadable) {
        return { ok: false, reason: `we could not read how this route checks the caller: ${route.identityGap}`, unassessed: true };
      }
      return { ok: true };

    case "unsigned_webhook":
      if (route.machineGated) {
        return { ok: false, reason: "we read a signature or shared-secret check in this route", unassessed: false };
      }
      if (!route.machineGateReadable || !route.identityReadable) {
        return {
          ok: false,
          reason: `we could not read what verifies this route: ${route.machineGateGap ?? route.identityGap}`,
          unassessed: true,
        };
      }
      return { ok: true };

    case "possession_gated":
      if (route.authenticated || route.machineGated || !route.identityReadable) {
        return { ok: false, reason: "a possession gate is only described on a route we read as anonymous", unassessed: false };
      }
      return { ok: true };

    default:
      return { ok: true };
  }
}

/**
 * Judges one hypothesis./**
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
  // An unrecognised fact citation is DROPPED, not fatal, as long as the
  // hypothesis is still grounded by a file we read. The invariant is unchanged:
  // an unverified citation never becomes evidence, because only the surviving
  // ids reach buildFindings and become claims. What changes is that one junk
  // field no longer discards an otherwise well-grounded finding.
  //
  // This cost a real vulnerability on a real repository. The model returned
  // citedFacts: ["anonymous"], copying a label off the route line, and the whole
  // finding went in the bin even though it cited the correct file. Two rounds of
  // prompt wording did not stop it, and a guard that throws away true findings
  // over a field the model misunderstands is the wrong shape.
  const verifiedFacts = citedFacts.filter(
    (fact) => typeof fact === "string" && (recon.facts?.has(fact) ?? false),
  );

  // Unless the facts WERE the grounding. A hypothesis with no file must cite at
  // least one fact we actually observed.
  if (citedFiles.length === 0 && verifiedFacts.length === 0) {
    return {
      allowed: false,
      reason: `cited fact "${citedFacts[0]}" was not observed in this run`,
    };
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

  // Last, because it is the only rule that judges the CLAIM rather than the
  // citation, and it should only run on a hypothesis that is otherwise sound.
  // `?.` is crash-safety, not permissiveness: the field is required by the type,
  // and an entry with no matching route fact is the same case as a hypothesis
  // with no route at all -- there is nothing of ours for it to contradict.
  const gate = recon.possessionGates?.get(h.entry);
  const compat = compatibility(h.attackClass as AttackClass, recon.routes?.get(h.entry), gate);
  // A SECOND REWORDING, also in one direction (R1 run 3, 2026-10-08). On a
  // route we read as signed in on every method and NOT narrowed to the
  // caller, "no sign-in needed" is wrong but "any signed-in user reaches
  // rows that are not theirs" is what our own facts describe. Refusing it
  // lost a planted IDOR that two earlier runs caught as authorization. The
  // claim goes to verification as missing_authorization under neutral
  // wording; the model's false sentence never reaches a founder.
  const route = recon.routes?.get(h.entry);
  if (!compat.ok && h.attackClass === "missing_authentication" && !gate && route && route.authenticated
      && route.identityReadable && !route.machineGated && !(route.unrefusedMethods?.length)
      && route.ownershipReadable && !route.ownershipFiltered) {
    const tables = route.tables.slice(0, 4).join(", ") || "its data";
    return { allowed: true, attackClass: "missing_authorization", citedFacts: verifiedFacts,
      title: "Any signed-in user may reach rows that are not theirs",
      consequence: `A signed-in caller reaches ${tables} through this route, and nothing we read narrows the query to their own rows.` };
  }
  if (!compat.ok) {
    return {
      allowed: false,
      reason: compat.reason,
      // Distinguishes "we could not assess this" from "this is wrong", so the
      // first can reach Coverage and the second is simply discarded.
      unassessed: compat.unassessed ? h.entry : undefined,
    };
  }

  // THE ONE REWORDING THIS GUARD DOES, and only in one direction.
  //
  // `missing_authentication` asserts that no credential of any kind is required.
  // On a route where we READ a possession gate, a row id bound to another
  // resource IS what is required, so the claim is wrong in its own terms and the
  // true sentence is `possession_gated`. Nothing is removed: the finding stays,
  // re-worded and at informational severity, with the gate named. A route with
  // no gate read keeps the critical, whatever the model or the shape suggests.
  // `missing_authorization` ("not narrowed to the caller") gets the same
  // rewording: a gate is only read on a route we read as anonymous, where there
  // is no caller to narrow by, so the claim is the same wrong sentence.
  if ((h.attackClass === "missing_authentication" || h.attackClass === "missing_authorization") && gate) {
    return { allowed: true, attackClass: "possession_gated", citedFacts: verifiedFacts };
  }

  return { allowed: true, attackClass: h.attackClass as AttackClass, citedFacts: verifiedFacts };
}

export interface GuardResult {
  admitted: (Hypothesis & { attackClass: AttackClass })[];
  rejected: { hypothesis: unknown; reason: string }[];
  /**
   * Routes where a claim was refused because the fact it rested on was one we
   * could not read -- NOT because the claim was wrong.
   *
   * Carried separately so it can reach the Coverage page. A refusal a customer
   * cannot see is indistinguishable from an assessment that came back clean,
   * which is the failure Coverage exists to prevent, now applied to our own
   * refusals rather than only to collectors that did not run.
   */
  unassessed: string[];
  /**
   * Entries the model named that are not in the inventory.
   *
   * "The model found nothing" and "we threw away everything the model found"
   * are OPPOSITE outcomes and the trace could not tell them apart. A run where
   * every hypothesis is rejected on a format mismatch rendered exactly like a
   * clean audit -- which is the "absent is not clean" failure again, one layer
   * down, inside our own diagnostics. This is what makes it loud.
   */
  unmatchedEntries: string[];
}

/**
 * Judges a batch. Rejections are RETURNED, not swallowed -- a run that discards
 * nine of ten proposals is telling us something about the prompt, and a silent
 * guard would hide it.
 */
export function guardHypotheses(raw: unknown, recon: ReconIndex): GuardResult {
  const result: GuardResult = { admitted: [], rejected: [], unassessed: [], unmatchedEntries: [] };
  if (!Array.isArray(raw)) {
    return { admitted: [], rejected: [{ hypothesis: raw, reason: "model did not return an array" }], unassessed: [], unmatchedEntries: [] };
  }

  for (const item of raw) {
    const verdict = judgeHypothesis(item as Hypothesis, recon);
    if (!verdict.allowed && verdict.unassessed && !result.unassessed.includes(verdict.unassessed)) {
      result.unassessed.push(verdict.unassessed);
    }
    if (!verdict.allowed && /is not in the route inventory/.test(verdict.reason)) {
      const named = (item as Hypothesis)?.entry;
      if (typeof named === "string" && !result.unmatchedEntries.includes(named)) {
        result.unmatchedEntries.push(named);
      }
    }
    if (verdict.allowed) {
      // citedFacts is replaced with only the ids we verified, so nothing
      // downstream can turn an unrecognised citation into a claim.
      result.admitted.push({
        ...(item as Hypothesis),
        attackClass: verdict.attackClass,
        citedFacts: verdict.citedFacts,
        ...(verdict.title ? { title: verdict.title } : {}),
        ...(verdict.consequence ? { consequence: verdict.consequence } : {}),
      });
    } else {
      result.rejected.push({ hypothesis: item, reason: verdict.reason });
    }
  }

  return result;
}

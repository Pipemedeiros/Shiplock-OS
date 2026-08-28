import type { Severity } from "@/lib/types";
import type { AttackPath } from "./attackPaths";
import type { AuthzFacts } from "./graph";
import type { RouteFact } from "./routeInventory";
import { SEVERITY_RANK } from "./providers";

// The defender's action space.
//
// `agent.ts` prosecutes: it proposes SQL to demonstrate a leak, and a guard
// decides whether each statement may run. This is the mirror image, and it
// guards a DIFFERENT risk. The prosecutor's danger is a model that does too
// much. The defender's danger is a model that talks us out of a real finding —
// the failure is silent, it looks like a clean report, and nobody notices until
// the breach.
//
// So the asymmetry is deliberate and must not be "balanced" later:
//
//   The prosecutor needs PERMISSION to act.
//   The defender needs PROOF to be believed.
//
// A defender claim changes nothing about a finding unless a deterministic
// verifier confirms it from facts a collector already observed. The model cannot
// introduce a fact, and "I could not check that" never counts in the defence's
// favour. Stated as the rule this module exists to enforce, from the research in
// docs/research/sast-evidence-architecture.md:
//
//   ABSENCE OF PROOF IS NOT PROOF OF A FALSE POSITIVE.
//
// Consequences that are load-bearing:
//  - Claims are a CLOSED SET. Free text is not a claim. A model that wants to
//    argue something we cannot mechanically check has, by construction, no way
//    to express it — which is the point, not a limitation to fix.
//  - A failed, empty, or malformed defender run leaves every finding EXACTLY as
//    it was. This module fails toward keeping findings, never toward hiding them.
//  - Nothing here can suppress. The strongest available outcome is `withdraw`,
//    reserved for claims that show the path does not exist as described, and
//    even that is recorded rather than deleted.

/**
 * Why a finding might not be exploitable.
 *
 * Every kind maps to a verifier below that reads facts we ALREADY collected.
 * Adding a kind means adding a verifier — a claim with no verifier can never be
 * confirmed, so it can never affect a finding.
 */
export type DefenceClaimKind =
  /** The route does not touch this table at all — the path's premise is wrong. */
  | "table_not_referenced"
  /** Page-level code, not a reachable API route. */
  | "route_not_api"
  /** The handler scopes its query to the caller (an ownership filter). */
  | "route_ownership_filtered"
  /** The handler resolves a user identity before touching data. */
  | "route_authenticated"
  /** Gated by a shared secret or signature (cron, webhook) rather than a session. */
  | "route_machine_gated"
  /** The store enforces authorization on this asset and we read the rules. */
  | "store_rule_enforced"
  /** The asset does not look like it holds personal or financial data. */
  | "table_not_sensitive";

export const DEFENCE_CLAIM_KINDS: readonly DefenceClaimKind[] = [
  "table_not_referenced",
  "route_not_api",
  "route_ownership_filtered",
  "route_authenticated",
  "route_machine_gated",
  "store_rule_enforced",
  "table_not_sensitive",
] as const;

/**
 * Claims that, when CONFIRMED, mean the path does not exist as the reasoner
 * described it — as opposed to existing but being less severe.
 *
 * Kept deliberately short. Everything else can only downrank, because "there is
 * a mitigating control" is a different statement from "this is not a path".
 */
const DISQUALIFYING: ReadonlySet<DefenceClaimKind> = new Set([
  "table_not_referenced",
  "route_not_api",
]);

export interface DefenceClaim {
  kind: DefenceClaimKind;
  /** Route path the claim is about, when it concerns a route. */
  route?: string;
  /** Qualified table name the claim is about, when it concerns an asset. */
  table?: string;
}

export type ClaimVerdict = "confirmed" | "refuted" | "unverifiable";

export interface VerifiedClaim extends DefenceClaim {
  verdict: ClaimVerdict;
  /** The fact that settled it, or why nothing could. Shown in the evidence trail. */
  basis: string;
}

/** Facts the verifiers read. Exactly what the collectors already produced. */
export interface DefenceEvidence {
  routes: RouteFact[];
  tables: AuthzFacts[];
}

export type DefenceOutcome = "unchanged" | "annotated" | "downranked" | "withdrawn";

export interface DefenceResult {
  pathId: string;
  outcome: DefenceOutcome;
  /** Severity after the defence. Never lower than INFO, never absent. */
  severity: Severity;
  claims: VerifiedClaim[];
  /** One line per confirmed or unverifiable claim, for the evidence ledger. */
  notes: string[];
}

const ORDERED: Severity[] = ["INFO", "WARNING", "CRITICAL"];

/** One step down, floored at INFO. A defence can soften a finding, never erase it. */
export function downrank(severity: Severity): Severity {
  const i = ORDERED.indexOf(severity);
  return i <= 0 ? "INFO" : ORDERED[i - 1];
}

function findRoute(evidence: DefenceEvidence, route: string | undefined): RouteFact | undefined {
  if (!route) return undefined;
  return evidence.routes.find((r) => r.path === route);
}

function findTable(evidence: DefenceEvidence, table: string | undefined): AuthzFacts | undefined {
  if (!table) return undefined;
  const wanted = table.toLowerCase();
  return evidence.tables.find(
    (t) => t.qualified.toLowerCase() === wanted || t.name.toLowerCase() === wanted
  );
}

/**
 * Checks one claim against collected facts.
 *
 * Three outcomes, and the third is the important one: `unverifiable` means the
 * subject of the claim is not in our facts at all — an unknown route, a table no
 * collector reported. That is NOT weak evidence for the defence. It is the
 * absence of evidence, and it is treated as such.
 */
export function verifyClaim(claim: DefenceClaim, evidence: DefenceEvidence): VerifiedClaim {
  const settle = (verdict: ClaimVerdict, basis: string): VerifiedClaim => ({ ...claim, verdict, basis });

  switch (claim.kind) {
    case "table_not_referenced": {
      const route = findRoute(evidence, claim.route);
      if (!route) return settle("unverifiable", `No route inventory entry for ${claim.route ?? "(unnamed)"}.`);
      if (!claim.table) return settle("unverifiable", "Claim named no table.");
      const bare = claim.table.split(".").pop()!.toLowerCase();
      const touches = route.tables.some((t) => t.toLowerCase() === bare);
      return touches
        ? settle("refuted", `${route.file} references ${bare}.`)
        : settle("confirmed", `${route.file} references no table named ${bare}.`);
    }

    case "route_not_api": {
      const route = findRoute(evidence, claim.route);
      if (!route) return settle("unverifiable", `No route inventory entry for ${claim.route ?? "(unnamed)"}.`);
      return route.isApiRoute
        ? settle("refuted", `${route.file} exports ${route.methods.join("/") || "a handler"} as an API route.`)
        : settle("confirmed", `${route.file} is not an API route handler.`);
    }

    case "route_ownership_filtered": {
      const route = findRoute(evidence, claim.route);
      if (!route) return settle("unverifiable", `No route inventory entry for ${claim.route ?? "(unnamed)"}.`);
      return route.ownershipFiltered
        ? settle("confirmed", `${route.file} scopes its query to the caller.`)
        : settle("refuted", `No ownership filter observed in ${route.file}.`);
    }

    case "route_authenticated": {
      const route = findRoute(evidence, claim.route);
      if (!route) return settle("unverifiable", `No route inventory entry for ${claim.route ?? "(unnamed)"}.`);
      if (!route.authenticated) return settle("refuted", `No user identity resolved in ${route.file}.`);
      // `via` is what makes this evidence rather than an assertion: it names the
      // module where the gate was seen. A route flagged authenticated with no
      // witness is a collector inference, and inference does not defend.
      return route.via.length > 0
        ? settle("confirmed", `${route.file} resolves a user identity via ${route.via.join(", ")}.`)
        : settle("unverifiable", `${route.file} looks authenticated but no gating module was identified.`);
    }

    case "route_machine_gated": {
      const route = findRoute(evidence, claim.route);
      if (!route) return settle("unverifiable", `No route inventory entry for ${claim.route ?? "(unnamed)"}.`);
      return route.machineGated
        ? settle("confirmed", `${route.file} is gated by a shared secret or signature.`)
        : settle("refuted", `No machine gate observed in ${route.file}.`);
    }

    case "store_rule_enforced": {
      const table = findTable(evidence, claim.table);
      if (!table) return settle("unverifiable", `No database facts for ${claim.table ?? "(unnamed)"}.`);
      // All three conditions, and rulesRead is the one that matters most: a table
      // with enforcement ON whose policies we never read is exactly where a
      // permissive rule hides. Confirming a defence there would recreate the bug
      // `rulesRead` was added to fix.
      if (!table.rulesRead) {
        return settle("unverifiable", `Access rules on ${table.qualified} were never read, so enforcement cannot be confirmed.`);
      }
      if (table.enforced !== true) {
        return settle("refuted", `Authorization is not enforced on ${table.qualified}.`);
      }
      if (table.unconditionalGrant) {
        return settle("refuted", `A rule on ${table.qualified} grants access unconditionally.`);
      }
      return settle("confirmed", `Authorization is enforced on ${table.qualified} and every rule was read.`);
    }

    case "table_not_sensitive": {
      const table = findTable(evidence, claim.table);
      if (!table) return settle("unverifiable", `No database facts for ${claim.table ?? "(unnamed)"}.`);
      return table.sensitive
        ? settle("refuted", `${table.qualified} looks like it holds personal or financial data.`)
        : settle("confirmed", `${table.qualified} does not look like it holds personal or financial data.`);
    }

    default: {
      // Unreachable for well-typed input; reached when a model emits a kind the
      // parser let through. Never confirmable.
      const exhaustive: never = claim.kind;
      return settle("unverifiable", `Unknown claim kind: ${String(exhaustive)}.`);
    }
  }
}

/**
 * Applies verified claims to one finding.
 *
 * The whole publication policy is here, and it is intentionally stingy:
 *
 *  - A confirmed DISQUALIFYING claim withdraws the path. It is recorded, not
 *    deleted — a withdrawn finding still carries why.
 *  - Otherwise, confirmed mitigating claims drop the severity ONE step,
 *    regardless of how many there are. Three weak mitigations are not a proof,
 *    and letting them stack would let a chatty model argue a CRITICAL down to
 *    nothing.
 *  - Unverifiable claims produce a NOTE and nothing else. This is the rule that
 *    keeps "we could not check" from reading as "it is fine".
 *  - Refuted claims change nothing. They are kept because a model that keeps
 *    proposing refuted defences is a signal worth seeing.
 */
export function applyDefence(path: AttackPath, claims: VerifiedClaim[]): DefenceResult {
  const confirmed = claims.filter((c) => c.verdict === "confirmed");
  const unverifiable = claims.filter((c) => c.verdict === "unverifiable");

  const notes = [
    ...confirmed.map((c) => `Counter-evidence confirmed: ${c.basis}`),
    ...unverifiable.map((c) => `Could not check: ${c.basis}`),
  ];

  const disqualifier = confirmed.find((c) => DISQUALIFYING.has(c.kind));
  if (disqualifier) {
    return {
      pathId: path.id,
      outcome: "withdrawn",
      severity: path.severity,
      claims,
      notes: [`Withdrawn — ${disqualifier.basis}`, ...notes.slice(1)],
    };
  }

  if (confirmed.length > 0) {
    return {
      pathId: path.id,
      outcome: "downranked",
      severity: downrank(path.severity),
      claims,
      notes,
    };
  }

  return {
    pathId: path.id,
    outcome: unverifiable.length > 0 ? "annotated" : "unchanged",
    severity: path.severity,
    claims,
    notes,
  };
}

/**
 * Whether a finding may be defended at all.
 *
 * Proven findings are exempt, and this is the sharpest rule in the module. If
 * the proving ground signed in as one synthetic tenant and read another's rows,
 * that happened. No amount of contextual argument makes an executed query
 * un-execute, and a defender allowed to soften it would be pure downside: it
 * could only ever turn a true finding into a quieter one.
 *
 * So the defender's territory is INFERENCE, and proof is what makes it
 * unnecessary. That is also why this is cheap to run — it only touches the
 * findings whose confidence was already qualified.
 */
export function isDefensible(path: AttackPath): boolean {
  return !path.id.startsWith("proven:");
}

/**
 * Parses model output into claims, discarding anything that is not a known kind
 * with a subject. Mirrors the posture of `checkAgentAction`: the model's output
 * is a candidate, never an instruction, and a malformed proposal is dropped
 * rather than repaired.
 */
export function parseClaims(raw: unknown): DefenceClaim[] {
  if (!Array.isArray(raw)) return [];
  const known = new Set<string>(DEFENCE_CLAIM_KINDS);
  const claims: DefenceClaim[] = [];

  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const { kind, route, table } = item as Record<string, unknown>;
    if (typeof kind !== "string" || !known.has(kind)) continue;
    const claim: DefenceClaim = { kind: kind as DefenceClaimKind };
    if (typeof route === "string" && route.trim()) claim.route = route.trim();
    if (typeof table === "string" && table.trim()) claim.table = table.trim();
    // A claim about nothing cannot be verified against anything.
    if (!claim.route && !claim.table) continue;
    claims.push(claim);
  }

  // Bounded, so a model cannot flood the verifier with variations until one lands.
  return claims.slice(0, 12);
}

/** Ranking helper shared with the reasoner, re-exported so callers need one import. */
export { SEVERITY_RANK };

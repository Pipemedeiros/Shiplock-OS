import type { Severity } from "@/lib/types";
import type { GithubFinding } from "@/lib/deep/githubScan";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { AttackClass, Hypothesis } from "./attackGuard";
import { renderPossessionGate, type PossessionGate } from "./possessionGate";
import type { StackReport } from "./stack";
import type { OpenByDesign } from "./signIn";

/** The claim that keeps a finding in an app open by design as To review
 * (P3, D1); `isConfirmed` reads it. */
export const OPEN_BY_DESIGN = "This app signs no one in by design";
const OPEN_CLASSES = new Set(["missing_authentication", "missing_authorization", "mass_assignment"]);

/**
 * Turns admitted hypotheses and deterministic hits into the findings a customer
 * reads.
 *
 * The important work here is not formatting. It is deciding, mechanically, two
 * things the product is not allowed to assert by hand:
 *
 *   confidence — a function of the claims and their origins. `proven` is
 *                reserved for lib/proving/*, which reproduces a finding on a
 *                replica; nothing in this file may ever produce it. Saying
 *                "proven" about something we only read would make the one label
 *                that means something mean nothing.
 *   fixKind    — the autonomy tier. A mechanical, testable change is a pull
 *                request; a small reversible config change is one click; a
 *                decision about the customer's product is theirs to make and we
 *                say so instead of guessing.
 */

export type Confidence = "proven" | "corroborated" | "inferred";
export type FixKind = "pr" | "one_click" | "manual";

export type ClaimOrigin =
  | "routes"
  | "imports"
  | "schema"
  | "stack"
  | "secrets"
  /**
   * A provider's live configuration, read through its API rather than from the
   * repository. This is a verified origin, so it counts toward `confidenceFrom`
   * and can legitimately lift a finding to `corroborated`: a fact observed in
   * the running system is stronger evidence than the same fact inferred from
   * code, which is the entire reason for connecting a service.
   */
  | "live"
  | "agent";

export interface Claim {
  claim: string;
  origin: ClaimOrigin;
  verified: boolean;
}

export interface AgentFinding {
  id: string;
  title: string;
  consequence: string;
  severity: Severity;
  confidence: Confidence;
  attackClass: AttackClass | "committed_secret" | "permission_gap";
  entry: string | null;
  file: string | null;
  blastRadius: string | null;
  fixKind: FixKind;
  claims: Claim[];
}

/** Severity per class. Not per model opinion -- the model does not set this. */
const SEVERITY: Record<string, Severity> = {
  missing_authorization: "CRITICAL",
  missing_authentication: "CRITICAL",
  unsigned_webhook: "CRITICAL",
  secret_exposure: "CRITICAL",
  server_boundary_crossed: "WARNING",
  injection: "WARNING",
  mass_assignment: "WARNING",
  unsafe_redirect: "WARNING",
  // A description of a share-link design, not a defect we can assert. What
  // would make it one -- the id being shown to someone who should not hold it
  // -- is exactly what we did not read, and the finding says so.
  possession_gated: "INFO",
};

/**
 * Which classes have a mechanical fix, and which are a judgement call.
 *
 * `server_boundary_crossed` is deliberately manual: where the boundary belongs
 * is an architecture decision, and a machine-authored answer would be a guess
 * dressed as a patch.
 */
const FIX_KIND: Record<string, FixKind> = {
  missing_authorization: "pr",
  missing_authentication: "pr",
  unsigned_webhook: "pr",
  injection: "pr",
  unsafe_redirect: "pr",
  secret_exposure: "manual",
  server_boundary_crossed: "manual",
  mass_assignment: "manual",
  // Whether a share link should exist is a product decision, and no
  // authorization logic is machine-authored here.
  possession_gated: "manual",
};

/**
 * Confidence from the evidence, with a hard ceiling.
 *
 * Two or more independent verified origins is corroborated; anything less is
 * inferred. `proven` is unreachable here by construction, and that is the
 * point: it is a capability of the proving ground, not a description a
 * static reader may award itself.
 */
export function confidenceFrom(claims: Claim[]): Confidence {
  const origins = new Set(claims.filter((c) => c.verified).map((c) => c.origin));
  return origins.size >= 2 ? "corroborated" : "inferred";
}

function routeClaims(route: RouteFact | undefined, stack: StackReport): Claim[] {
  if (!route) return [];

  const claims: Claim[] = [
    {
      claim: route.machineGated
        ? "The route is gated by a shared secret or signature."
        : route.authenticated && route.unrefusedMethods?.length
          ? `The route resolves a user, but nothing in its ${route.unrefusedMethods.join(" or ")} handler refuses a caller who is not signed in${route.refusalGap ? `; ${route.refusalGap}` : ""}.`
        : route.authenticated
          ? "The route resolves a user, so this is a gap between customers rather than an open door."
          : route.identityReadable
            ? "The route is reachable without any credential."
            : `We could not read how this route checks the caller: ${route.identityGap}.`,
      origin: "routes",
      // An admission that we could not read something is not an observation.
      // Marking it verified would let a gap in our own reading count toward
      // `corroborated`, which is the opposite of what confidence means here.
      verified: route.machineGated || route.authenticated || route.identityReadable,
    },
  ];

  if (route.tables.length > 0) {
    claims.push({
      claim: `It reads or writes ${route.tables.join(", ")}.`,
      origin: "schema",
      verified: true,
    });
  }

  if (!route.ownershipFiltered && route.tables.length > 0) {
    // A claim marked `verified` counts toward `corroborated`, so it must be an
    // OBSERVATION. On a route whose scoping we could not follow, the honest
    // statement is the gap itself, unverified -- otherwise a hole in our reading
    // raises our confidence, which is exactly backwards.
    claims.push(
      route.ownershipReadable
        ? {
            claim: "No column in the query belongs to the caller, so nothing narrows the result to them.",
            origin: "imports",
            verified: true,
          }
        : {
            claim: `We could not follow how this query is narrowed to the caller: ${route.ownershipGap}.`,
            origin: "imports",
            verified: false,
          },
    );
  }

  // Whether an unscoped query is actually exploitable turns on one thing: does
  // anything below it still filter? A service-role client answers that
  // definitively, because it bypasses row policies entirely. Auditing two real
  // repositories showed both shapes side by side, one cancelling any
  // subscription through a service-role client and one updating any row through
  // the caller's own session, where a row policy may well be stopping it. They
  // are not the same claim and must not be stated with the same certainty.
  if (route.usesServiceRole && route.serviceRoleReadable) {
    claims.push({
      claim:
        "The route uses a service-role client, which bypasses row policies, so nothing below the query filters it either.",
      origin: "imports",
      verified: true,
    });
  }

  const auth = stack.tools.find((t) => t.kind === "auth");
  if (auth) {
    claims.push({
      claim: `Identity is handled by ${auth.name} (${auth.evidence}).`,
      origin: "stack",
      verified: true,
    });
  }

  return claims;
}

export interface BuildFindingsInput {
  /** provenStatement: the consequence is a verifier's statement proven with quoted lines. */
  admitted: (Hypothesis & { attackClass: AttackClass; provenStatement?: true;
    /** Quoted lines a verifier gave and checkVerdicts re-read in the file. */
    proof?: { role: string; path: string; line: number; quote: string }[] })[];
  deterministic: GithubFinding[];
  routes: RouteFact[];
  stack: StackReport;
  repositoryId: string;
  hasDatabase: boolean;
  /**
   * Live provider facts observed this run, keyed by the id the guard checked.
   * A hypothesis that cited one gets it back as a VERIFIED claim, because we
   * read it from the provider rather than taking the model's word for it.
   */
  liveFacts?: { id: string; statement: string }[];
  /**
   * Possession gates read this run, keyed by route path. A `possession_gated`
   * finding is rendered from its gate, never from the model's prose, which was
   * written for a missing login.
   */
  possessionGates?: ReadonlyMap<string, PossessionGate>;
  /** Anonymous routes whose only way in is a random-minted request id
   * (possessionGate.ts `oneIdAccess`); such findings cap at WARNING (Q21). */
  oneIdAccess?: ReadonlyMap<string, PossessionGate>;
  /** Where an app with no sign-in says it is open by design (signIn.ts). */
  openByDesign?: OpenByDesign | null;
}

export function buildFindings(input: BuildFindingsInput): AgentFinding[] {
  const byPath = new Map(input.routes.map((r) => [r.path, r]));
  const findings: AgentFinding[] = [];

  for (const admitted of input.admitted) {
    const route = byPath.get(admitted.entry);

    // Rendered from what we read, and nothing else. The guard only produces
    // this class where a gate was read, so a missing gate here is a wiring
    // fault on our side. It must not make a finding vanish: it falls back to
    // the claim the guard reworded, which keeps the critical standing.
    const gate = admitted.attackClass === "possession_gated" ? input.possessionGates?.get(admitted.entry) : undefined;
    const h =
      admitted.attackClass === "possession_gated" && !gate
        ? { ...admitted, attackClass: "missing_authentication" as const }
        : admitted;
    if (gate) {
      const rendered = renderPossessionGate(gate);
      findings.push({
        id: `agent:${h.attackClass}:${h.entry}`,
        title: rendered.title,
        consequence: rendered.consequence,
        severity: SEVERITY.possession_gated,
        confidence: confidenceFrom(rendered.claims),
        attackClass: h.attackClass,
        entry: h.entry,
        file: gate.file,
        blastRadius: route && route.tables.length ? route.tables.join(", ") : null,
        fixKind: FIX_KIND.possession_gated,
        claims: rendered.claims,
      });
      continue;
    }
    // A cited fact becomes a claim of its own, marked verified: we read it from
    // the provider, so it is evidence rather than the model's assertion. This
    // is what lets a live connection raise a finding from inferred to
    // corroborated, which is the whole return on connecting a service.
    const byFactId = new Map((input.liveFacts ?? []).map((f) => [f.id, f]));
    const liveClaims: Claim[] = (h.citedFacts ?? [])
      .map((id) => byFactId.get(id))
      .filter((f): f is { id: string; statement: string } => Boolean(f))
      .map((f) => ({ claim: f.statement, origin: "live" as const, verified: true }));

    const claims: Claim[] = [
      ...routeClaims(route, input.stack),
      ...liveClaims,
      { claim: h.consequence, origin: "agent", verified: false },
      // Proof (A2): each quote was found on its cited line, so it is verified.
      ...(h.proof ?? []).slice(0, 8).map((c): Claim => ({
        claim: `Proof, ${c.role}: ${c.path}:${c.line} ${c.quote.trim()}`, origin: "agent", verified: true })),
    ];

    // An unscoped query through the CALLER'S OWN session may still be stopped
    // by a row policy we never read. Saying so is not hedging: it is the
    // difference between a finding and a guess, and connecting a database is
    // what resolves it. A service-role route needs no such caveat, because
    // nothing below it filters.
    // Only where a declarative policy engine could actually be compensating.
    // Supabase and Firebase enforce rules inside the store, so an unscoped
    // query through the caller's own session may still be filtered there. An
    // app talking to plain Postgres through Drizzle or Prisma has no such
    // layer: the query IS the authorization, and hedging it would understate a
    // real finding.
    // `databaseUnknown` is the readability pair this type already carries, and
    // it was going unread. Stack detection requires a real import, so a database
    // reached through a renamed wrapper or a monorepo package leaves `tools`
    // empty -- and an empty list was being treated as "no policy engine",
    // silently disabling the hedge and stating every unscoped finding at full
    // confidence with no "we did not read your row policies" caveat.
    //
    // Undetected is not absent: when we could not identify a database at all, we
    // keep the hedge. The cost is a slightly softer finding on an app that
    // genuinely has no policy engine; the alternative is overclaiming on one
    // that does.
    const usesPolicyEngine =
      input.stack.databaseUnknown ||
      input.stack.tools.some(
        (t) => t.kind === "database" && (t.id === "supabase" || t.id === "firebase"),
      );
    const rlsCouldStillProtect =
      !input.hasDatabase &&
      usesPolicyEngine &&
      Boolean(route) &&
      // Unknown must not remove the hedge: a service-role mention we could only
      // see inside a string is not proof the store is bypassed.
      (!route!.usesServiceRole || !route!.serviceRoleReadable) &&
      // The hedge must survive an unreadable filter. This is already true by
      // polarity -- ownershipFiltered is false whenever it is unreadable -- but
      // stating it keeps the intent explicit and the invariant checkable, rather
      // than correct by accident of how two fields happen to line up.
      (!route!.ownershipFiltered || !route!.ownershipReadable);

    // Q21 (Felipe, 2026-09-28): the only way in is a random-minted id the caller
    // must already hold. Capped at WARNING, never removed, and said.
    const oneId = (h.attackClass === "missing_authentication" || h.attackClass === "missing_authorization")
      && route !== undefined && route.identityReadable && !route.authenticated && !route.machineGated
      ? input.oneIdAccess?.get(h.entry) : undefined;
    if (oneId) {
      claims.push({
        claim: `The only way in is a ${oneId.model} id (${oneId.param}), minted by ${oneId.mint.expression}, so a caller needs that id before this answers.`,
        origin: "schema",
        verified: true,
      });
    }

    if (rlsCouldStillProtect) {
      claims.push({
        claim:
          "We did not read your row policies, so one of them may still be narrowing this query. Connect your database to settle it.",
        origin: "schema",
        verified: false,
      });
    }

    // P3 (D1): no other account to reach, and openness is the founder's call.
    // The finding and its proof stay; it is To review, never an issue.
    if (input.openByDesign && OPEN_CLASSES.has(h.attackClass)) {
      const o = input.openByDesign;
      claims.push({
        claim: `${OPEN_BY_DESIGN} (${o.file}:${o.line} ${o.reason}), so there is no other account to reach. Anyone who can reach it can do this; whether it should be open is your call.`,
        origin: "routes",
        verified: true,
      });
    }

    // CRITICAL NEEDS EVIDENCE OUTSIDE THE REPOSITORY (Felipe, 2026-09-29,
    // delegated). Three held-out corpora put repository-only admitted findings
    // near 5% precision (Q23 to Q26). A model-proposed finding that cites no
    // live provider fact is capped at WARNING and says so; a proof or a live
    // fact is what earns CRITICAL. Deterministic checks are not affected.
    const repositoryOnlyCritical = SEVERITY[h.attackClass] === "CRITICAL" && liveClaims.length === 0;
    if (repositoryOnlyCritical) {
      claims.push({
        claim: "We read this only from your code; nothing outside the repository confirms it yet, so treat it as one to review.",
        origin: "schema",
        verified: true,
      });
    }

    // On a route we READ as anonymous there is no caller to narrow by, so the
    // model's story for missing_authorization ("across workspaces") is a
    // mechanism we never read. Say what we read instead; the model's sentence
    // stays in the claims, unverified (Q16).
    // A statement proven with quoted lines stands: on CORPUS-5's agent path both
    // blind labelers agreed 19 of 24 verified authorization findings were real,
    // and 17 of them read wrong because route facts that missed a sign-in
    // helper (tRPC protectedProcedure, ctx.auth checks) replaced the
    // verifier's accurate sentence with "Anyone can call this".
    const proven = h.provenStatement === true;
    const readAsAnonymous = !proven && h.attackClass === "missing_authorization" && route !== undefined
      && route.identityReadable && !route.authenticated && !route.machineGated;
    const tables = route ? route.tables : [];
    const tableWords = tables.length > 1 ? `${tables.slice(0, -1).join(", ")} and ${tables[tables.length - 1]}` : tables.join("");
    // Q26: the same on a route read as signed in whose query we read as not
    // narrowed to the caller. CORPUS-3's model titles described these
    // signed-in IDORs as anonymous; only what we read is stated.
    const readAsSignedInUnscoped = !proven && h.attackClass === "missing_authorization" && route !== undefined
      && route.identityReadable && route.authenticated && !route.machineGated
      && route.ownershipReadable && !route.ownershipFiltered;
    findings.push({
      // Stable across runs: the same gap on the same entry keeps its identity,
      // so the diff engine does not re-alert it every pass.
      id: `agent:${h.attackClass}:${h.entry}`,
      title: readAsAnonymous ? "Anyone can call this without signing in"
        : readAsSignedInUnscoped ? "Signed-in callers are not limited to their own rows" : h.title,
      consequence: readAsAnonymous
        ? `We read no sign-in check on ${h.entry}, and its query${tableWords ? ` on ${tableWords}` : ""} is not narrowed to a caller, so the request alone decides what it reads or changes.`
        : readAsSignedInUnscoped
          ? `We read a sign-in check on ${h.entry}, but its query${tableWords ? ` on ${tableWords}` : ""} is not narrowed to the signed-in caller, so any signed-in user's request decides which rows it reads or changes.`
          : h.consequence,
      severity: oneId || repositoryOnlyCritical ? "WARNING" : (SEVERITY[h.attackClass] ?? "WARNING"),
      // Capped, not computed, when a row policy could still be enforcing this.
      // The origin count says several collectors agree the query is unscoped;
      // it cannot say the database is not compensating, and reporting
      // "corroborated" would claim exactly that.
      confidence: rlsCouldStillProtect ? "inferred" : confidenceFrom(claims),
      attackClass: h.attackClass,
      entry: h.entry,
      file: route?.file ?? h.citedFiles[0] ?? null,
      blastRadius: route && route.tables.length ? route.tables.join(", ") : null,
      fixKind: FIX_KIND[h.attackClass] ?? "manual",
      claims,
    });
  }

  for (const d of input.deterministic) {
    findings.push({
      id: d.id,
      title: d.title,
      consequence: d.consequence,
      severity: d.severity,
      // A committed credential is read directly out of the file. There is no
      // inference involved, but it is still not `proven` -- nothing was run.
      confidence: "corroborated",
      attackClass: "committed_secret",
      entry: null,
      file: d.id.split(":").pop() ?? null,
      blastRadius: null,
      // Rotating a leaked key is the customer's to do; we cannot rotate a
      // credential we do not hold, and a PR removing it does not un-leak it.
      fixKind: "manual",
      claims: [
        { claim: "The value matches a real credential shape and is committed to the repository.", origin: "secrets", verified: true },
        { claim: "Anyone with read access to this repository, now or in its history, has it.", origin: "secrets", verified: true },
      ],
    });
  }

  // Permission gaps read from source (Step 7C). Rendered from the rule the
  // repository itself states, never from a model. A WARNING and a manual fix:
  // whether the weaker path is intended is a business decision (AGENTS.md).
  const pathByFile = new Map(input.routes.map((r) => [r.file, r.path]));
  for (const route of input.routes) {
    for (const gap of route.permissionGaps ?? []) {
      const witnessPath = pathByFile.get(gap.witness.file) ?? gap.witness.file;
      const held = gap.requires.length ? gap.requires.join(" and ") : "no permission for it";
      findings.push({
        id: `agent:permission_gap:${gap.method}:${route.path}:${gap.model}`,
        title: `${gap.method} ${route.path} changes ${gap.model} records with only ${held}`,
        consequence: `Elsewhere in this app, changing ${gap.model} records requires ${gap.expected} `
          + `(${gap.witness.method} ${witnessPath}). Here, a user holding only ${held} can do it. `
          + "If that is not intended, require the same permission here. Whether it is intended is your call.",
        severity: "WARNING",
        confidence: "inferred",
        attackClass: "permission_gap",
        entry: route.path,
        file: gap.file,
        blastRadius: gap.model,
        fixKind: "manual",
        claims: [
          { claim: `${gap.method} ${route.path} declares ${held} and writes ${gap.model}.`, origin: "routes", verified: true },
          { claim: `${gap.witness.method} ${witnessPath} declares ${gap.expected} for the same write.`, origin: "routes", verified: true },
        ],
      });
    }
  }

  const order: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };
  return findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

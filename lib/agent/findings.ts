import type { Severity } from "@/lib/types";
import type { GithubFinding } from "@/lib/deep/githubScan";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { AttackClass, Hypothesis } from "./attackGuard";
import type { StackReport } from "./stack";

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

export type ClaimOrigin = "routes" | "imports" | "schema" | "stack" | "secrets" | "agent";

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
  attackClass: AttackClass | "committed_secret";
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
        : route.authenticated
          ? "The route resolves a user, so this is a gap between customers rather than an open door."
          : "The route is reachable without any credential.",
      origin: "routes",
      verified: true,
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
    claims.push({
      claim: "No column in the query belongs to the caller, so nothing narrows the result to them.",
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
  admitted: (Hypothesis & { attackClass: AttackClass })[];
  deterministic: GithubFinding[];
  routes: RouteFact[];
  stack: StackReport;
  repositoryId: string;
  hasDatabase: boolean;
}

export function buildFindings(input: BuildFindingsInput): AgentFinding[] {
  const byPath = new Map(input.routes.map((r) => [r.path, r]));
  const findings: AgentFinding[] = [];

  for (const h of input.admitted) {
    const route = byPath.get(h.entry);
    const claims: Claim[] = [
      ...routeClaims(route, input.stack),
      { claim: h.consequence, origin: "agent", verified: false },
    ];

    findings.push({
      // Stable across runs: the same gap on the same entry keeps its identity,
      // so the diff engine does not re-alert it every pass.
      id: `agent:${h.attackClass}:${h.entry}`,
      title: h.title,
      consequence: h.consequence,
      severity: SEVERITY[h.attackClass] ?? "WARNING",
      confidence: confidenceFrom(claims),
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

  const order: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };
  return findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

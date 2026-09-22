import Anthropic from "@anthropic-ai/sdk";
import type { AttackPath } from "./attackPaths";
import {
  applyDefence,
  isDefensible,
  parseClaims,
  verifyClaim,
  type DefenceClaim,
  type DefenceEvidence,
  type DefenceResult,
} from "./defenderGuard";

// The defence pass.
//
// The reasoner produces attack paths by inference: an anonymous route reaches a
// table whose rules we could not read, therefore a leak is possible. That is the
// right default — silence is the dangerous answer in security — but inference is
// also where false positives live, and a founder who is shown three paths that
// a middleware already covers stops reading the fourth.
//
// So before an inferred path is published, a model is asked the question the
// reasoner never asks: WHY MIGHT THIS NOT BE EXPLOITABLE? It may only answer in
// a closed vocabulary of claims, each of which a deterministic verifier checks
// against facts the collectors already produced (defenderGuard.ts). The model
// contributes suspicion, never authority.
//
// Cost, following narrative.ts: one batched call per pass, Haiku, and only for
// paths that survive to publication. A pass with no inferred paths calls Claude
// zero times. This module is not wired into the production monitoring path.
//
// FAILURE POSTURE, and it is the opposite of most of this codebase: everything
// here fails toward KEEPING findings. A timeout, a malformed response, an
// unparseable claim, a missing API key — every one of them leaves the findings
// exactly as the reasoner ranked them. A defender that silently degrades makes
// reports look cleaner, and a security product whose failure mode is "looks
// clean" is worse than one that has no defender at all.

const MODEL = "claude-haiku-4-5-20251001";
const TIMEOUT_MS = 20_000;
const MAX_PATHS_PER_CALL = 8;

// Within the intended 300-token system-prompt budget. The claim vocabulary is
// stated as an enumeration because that IS the interface — anything outside it
// is discarded by parseClaims before a verifier ever sees it.
const SYSTEM_PROMPT = `You look for reasons a reported security finding might NOT be exploitable.

You receive findings, the routes involved, and what is known about the data they touch. For each finding, propose any counter-evidence you genuinely suspect. Propose nothing if you have no reason to.

You may ONLY use these claim kinds:
- table_not_referenced: the route does not actually touch that table
- route_not_api: it is page code, not a reachable API endpoint
- route_ownership_filtered: the handler scopes the query to the caller
- route_authenticated: the handler resolves a user identity first
- route_machine_gated: it is gated by a cron secret or webhook signature
- store_rule_enforced: the database enforces access rules on that table
- table_not_sensitive: that table holds no personal or financial data

Rules:
- Each claim names the finding id, a kind, and a route or table it concerns.
- Claim only what the supplied facts suggest. Do not invent routes, tables or controls.
- Every claim is checked against collected facts. An unsupported claim is discarded, so guessing costs you and gains nothing.
- Silence is a valid answer. Findings with no claims stay as they are.

Return JSON only: {"defences":[{"id":"<finding id>","claims":[{"kind":"<kind>","route":"<path>","table":"<name>"}]}]}`;

export interface DefenceRunResult {
  /** Path id -> outcome. Paths absent were not defended and stand unchanged. */
  results: Map<string, DefenceResult>;
  tokensIn: number;
  tokensOut: number;
  /** Why the pass did nothing, when it did nothing. For logs, not customers. */
  skipped?: string;
}

const EMPTY: DefenceRunResult = { results: new Map(), tokensIn: 0, tokensOut: 0 };

/** Proposes claims per finding id. Injected so the loop is testable without a model. */
export type DefenceProposer = (
  paths: AttackPath[],
  evidence: DefenceEvidence
) => Promise<Map<string, DefenceClaim[]>>;

/**
 * Compact prompt input.
 *
 * Deliberately NOT the whole graph. The model gets the finding, the routes it
 * names and the tables it names — enough to suspect a mitigation, not enough to
 * reason its way into new territory. This also keeps the call inside the token
 * budget on a customer with hundreds of routes.
 */
function describe(paths: AttackPath[], evidence: DefenceEvidence): string {
  const routeLines = evidence.routes
    .slice(0, 60)
    .map(
      (r) =>
        `  ${r.path} [${r.methods.join(",") || "-"}] tables=${r.tables.join(",") || "-"} ` +
        `auth=${r.authenticated} machine=${r.machineGated} owned=${r.ownershipFiltered}`
    )
    .join("\n");

  const tableLines = evidence.tables
    .slice(0, 60)
    .map(
      (t) =>
        `  ${t.qualified} enforced=${t.enforced ?? "unknown"} rulesRead=${t.rulesRead} ` +
        `unconditional=${t.unconditionalGrant} sensitive=${t.sensitive}`
    )
    .join("\n");

  const findingLines = paths
    .map((p) => `  ${p.id} [${p.severity}] ${p.title}\n    ${p.evidence.map((e) => e.fact).join(" | ")}`)
    .join("\n");

  return `findings:\n${findingLines}\n\nroutes:\n${routeLines || "  (none)"}\n\ntables:\n${tableLines || "  (none)"}`;
}

/** Asks the model for counter-evidence. Any failure yields an empty map. */
export function claudeDefenceProposer(): DefenceProposer {
  return async (paths, evidence) => {
    const out = new Map<string, DefenceClaim[]>();
    try {
      const client = new Anthropic();
      const response = await client.messages.create(
        {
          model: MODEL,
          max_tokens: 900,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: describe(paths, evidence) }],
        },
        { timeout: TIMEOUT_MS, maxRetries: 0 }
      );

      console.log(
        `[defender] model=${MODEL} input=${response.usage.input_tokens} output=${response.usage.output_tokens} paths=${paths.length}`
      );

      const text = response.content.filter((b) => b.type === "text").map((b) => b.text).join("");
      const match = /\{[\s\S]*\}/.exec(text);
      if (!match) return out;

      const parsed = JSON.parse(match[0]) as { defences?: unknown };
      if (!Array.isArray(parsed.defences)) return out;

      const known = new Set(paths.map((p) => p.id));
      for (const entry of parsed.defences) {
        if (typeof entry !== "object" || entry === null) continue;
        const { id, claims } = entry as Record<string, unknown>;
        // A defence for a finding we did not send is discarded outright — that
        // is the model addressing something outside the batch.
        if (typeof id !== "string" || !known.has(id)) continue;
        const parsedClaims = parseClaims(claims);
        if (parsedClaims.length > 0) out.set(id, parsedClaims);
      }
      return out;
    } catch (err) {
      console.error("[defender] proposal failed:", err instanceof Error ? err.message : err);
      return out;
    }
  };
}

/**
 * Runs the defence over a set of reasoner findings.
 *
 * Proven findings are filtered out before the model is called — see
 * `isDefensible`. Everything else is batched into one request, and each returned
 * claim is verified against collected facts before it can affect anything.
 */
export async function runDefence(
  paths: AttackPath[],
  evidence: DefenceEvidence,
  propose: DefenceProposer = claudeDefenceProposer()
): Promise<DefenceRunResult> {
  const defensible = paths.filter(isDefensible).slice(0, MAX_PATHS_PER_CALL);
  if (defensible.length === 0) {
    return { ...EMPTY, skipped: "no defensible paths" };
  }

  let proposals: Map<string, DefenceClaim[]>;
  try {
    proposals = await propose(defensible, evidence);
  } catch (err) {
    console.error("[defender] proposer threw:", err instanceof Error ? err.message : err);
    return { ...EMPTY, skipped: "proposer failed" };
  }

  const results = new Map<string, DefenceResult>();
  for (const path of defensible) {
    const claims = proposals.get(path.id);
    if (!claims || claims.length === 0) continue;
    const verified = claims.map((c) => verifyClaim(c, evidence));
    const result = applyDefence(path, verified);
    // `unchanged` means every claim was refuted — nothing to record on the finding.
    if (result.outcome !== "unchanged") results.set(path.id, result);
  }

  return { results, tokensIn: 0, tokensOut: 0 };
}

/**
 * Applies defence results to a path list.
 *
 * Withdrawn paths are REMOVED from what the customer sees but returned
 * separately, because a finding we decided not to show is exactly the kind of
 * thing that must remain auditable — the same reasoning as recording refused
 * agent queries in `summariseAttempts`.
 */
export function applyDefenceResults(
  paths: AttackPath[],
  results: Map<string, DefenceResult>
): { published: AttackPath[]; withdrawn: { path: AttackPath; result: DefenceResult }[] } {
  const published: AttackPath[] = [];
  const withdrawn: { path: AttackPath; result: DefenceResult }[] = [];

  for (const path of paths) {
    const result = results.get(path.id);
    if (!result) {
      published.push(path);
      continue;
    }
    if (result.outcome === "withdrawn") {
      withdrawn.push({ path, result });
      continue;
    }
    published.push({
      ...path,
      severity: result.severity,
      // Counter-evidence joins the same evidence array the reasoner built, so a
      // finding carries the case against it alongside the case for it.
      evidence: [
        ...path.evidence,
        ...result.notes.map((fact) => ({ collector: "source" as const, fact })),
      ],
    });
  }

  return { published, withdrawn };
}

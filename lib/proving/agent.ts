import type { Severity } from "@/lib/types";
import { assertAgentAction, checkAgentAction, summariseAttempts, type AgentAttempt } from "./agentGuard";
import { TENANT_B } from "./tenantProbe";

// The adversarial agent.
//
// The deterministic probe asks one question: does `owner = other_tenant` return
// rows? That catches the common case and misses everything shaped differently —
// a policy leaking through a second column, an OR branch that is always true for
// some role, a view that bypasses the check, a join that reintroduces rows the
// policy removed. Enumerating those in advance is exactly the work an LLM is
// better at than a rule list, because the space is open-ended.
//
// So the model proposes queries and a deterministic guard decides whether each
// may run (lib/proving/agentGuard.ts). That split is the whole design: the model
// contributes ideas, never authority. It cannot widen its own permissions,
// because nothing it emits is interpreted as a permission — its output is only
// ever a candidate SELECT that gets judged by code it cannot influence.
//
// WHAT THIS IS NOT: it does not touch a running application, send HTTP requests,
// test authentication flows, or chain findings across surfaces. It reads inside
// one disposable schema. Strix-class agentic exploitation drives a browser and a
// proxy against a live app; this is a long way from that and should not be
// described as equivalent.
//
// Blast radius is bounded before capability: a hard cap on rounds and queries,
// and every proposal recorded whether it ran or not. ShipLock makes no model
// call (Felipe, 2026-10-01): the proposer is injected, and without one the
// table stays unproven, never clean.

const MAX_ROUNDS = 3;
const MAX_QUERIES_PER_ROUND = 4;

export interface AgentContext {
  schema: string;
  table: string;
  columns: string[];
  policies: { name: string; cmd: string; using: string | null }[];
}

export interface AgentFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
  proven: true;
  attempts: AgentAttempt[];
}

/** Executes one validated query against the replica. Injected, so the loop is testable. */
type QueryRunner = (sql: string) => Promise<Record<string, unknown>[]>;

/** Proposes queries. Injected so the loop can be tested without a model. */
export type Proposer = (context: AgentContext, previous: AgentAttempt[]) => Promise<string[]>;

/**
 * Did this result actually expose the other tenant?
 *
 * Requires B's identifier to appear in a returned row. A row count alone is not
 * evidence — a query can return rows that are all A's own, and treating any
 * non-empty result as a leak would manufacture findings out of correct
 * behaviour. This is the difference between an agent that finds things and one
 * that cries wolf.
 */
export function resultProvesLeak(rows: Record<string, unknown>[]): boolean {
  if (!Array.isArray(rows) || rows.length === 0) return false;
  return rows.some((row) =>
    Object.values(row).some((value) => typeof value === "string" && value.includes(TENANT_B))
  );
}

/**
 * Runs the agent against one replicated table.
 *
 * Every proposal is recorded — including refusals — because what the agent TRIED
 * inside a customer's replica is something we should be able to show, not
 * something to discover later.
 */
export async function runAdversarialAgent(
  context: AgentContext,
  runQuery: QueryRunner,
  propose: Proposer,
  maxRounds = MAX_ROUNDS
): Promise<{ finding: AgentFinding | null; attempts: AgentAttempt[] }> {
  const attempts: AgentAttempt[] = [];

  for (let round = 0; round < maxRounds; round++) {
    const proposals = await propose(context, attempts);
    if (proposals.length === 0) break;

    for (const sql of proposals.slice(0, MAX_QUERIES_PER_ROUND)) {
      const check = checkAgentAction(sql, context.schema);
      if (!check.allowed) {
        attempts.push({ sql, allowed: false, reason: check.reason });
        continue;
      }

      let rows: Record<string, unknown>[] = [];
      try {
        // Belt and braces: the throwing guard runs again immediately before
        // execution, so a future refactor that skips the check above still
        // cannot reach the database.
        assertAgentAction(sql, context.schema);
        rows = await runQuery(sql);
      } catch (err) {
        attempts.push({ sql, allowed: true, reason: "", error: err instanceof Error ? err.message : "failed" });
        continue;
      }

      attempts.push({ sql, allowed: true, reason: "", rows });

      if (resultProvesLeak(rows)) {
        return { finding: buildAgentFinding(context, sql, rows, attempts), attempts };
      }
    }
  }

  return { finding: null, attempts };
}

function buildAgentFinding(
  context: AgentContext,
  sql: string,
  rows: Record<string, unknown>[],
  attempts: AgentAttempt[]
): AgentFinding {
  return {
    id: `proven:agent_tenant_leak:${context.schema.replace(/^proving_/, "")}:${context.table}`,
    severity: "CRITICAL",
    title: `Confirmed: another user's rows in ${context.table} are reachable`,
    consequence:
      `We rebuilt ${context.table} and its policies on our own infrastructure (your schema, none of your data) created two synthetic users, and signed in as the first. ` +
      `This query returned ${rows.length} row${rows.length === 1 ? "" : "s"} belonging to the second user:\n\n${sql}\n\n` +
      `That is not a warning derived from reading your policy; it is what came back when we ran it. Your real table has the same policies, so a signed-in user of your app can reach other users' rows the same way. ` +
      `${summariseAttempts(attempts)} ` +
      `The fix is a policy that ties every row to its owner via auth.uid(). We will re-run this exact query afterwards and close the finding only when it returns nothing.`,
    proven: true,
    attempts,
  };
}

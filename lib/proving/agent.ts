import Anthropic from "@anthropic-ai/sdk";
import type { Severity } from "@/lib/types";
import { assertAgentAction, checkAgentAction, summariseAttempts, type AgentAttempt } from "./agentGuard";
import { TENANT_A, TENANT_B } from "./tenantProbe";

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
// Cost and blast radius are bounded before capability: a hard cap on rounds and
// queries, a small model by default, and every proposal recorded whether it ran
// or not.

const MAX_ROUNDS = 3;
const MAX_QUERIES_PER_ROUND = 4;
const TIMEOUT_MS = 30_000;

// Haiku by default to keep optional proof reasoning bounded. The task is
// generating candidate SQL against a described schema, not deep reasoning, and
// the guard means a weaker proposal is cheap rather than dangerous.
const MODEL = "claude-haiku-4-5-20251001";

const SYSTEM_PROMPT = `You test whether a Postgres row-level-security policy isolates tenants.

You are given one table in schema {schema}, its columns, and its policies. Two synthetic tenants exist:
A = ${TENANT_A} (you are signed in as A)
B = ${TENANT_B}

Propose SELECT queries that would return rows belonging to B. If any does, the policy fails to isolate tenants.

Rules:
- SELECT only. One statement. No semicolons.
- Every table must be schema-qualified with {schema}.
- Never reference pg_catalog, information_schema, auth.users, storage, or any other schema.
- auth.uid() is allowed.

Return JSON only: {"queries":["...","..."]}. No prose.`;

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
export type QueryRunner = (sql: string) => Promise<Record<string, unknown>[]>;

/** Proposes queries. Injected so the loop can be tested without a model. */
export type Proposer = (context: AgentContext, previous: AgentAttempt[]) => Promise<string[]>;

/**
 * Asks the model for candidate queries.
 *
 * Failure returns an empty list, never a throw: an agent that cannot think of
 * anything is a quiet run, and the deterministic probe has already covered the
 * common case regardless.
 */
export function claudeProposer(): Proposer {
  return async (context, previous) => {
    const client = new Anthropic();
    const schemaDescription =
      `table: ${context.schema}.${context.table}\n` +
      `columns: ${context.columns.join(", ")}\n` +
      `policies:\n` +
      context.policies.map((p) => `  ${p.name} (${p.cmd}) USING ${p.using ?? "-"}`).join("\n");

    const tried =
      previous.length > 0
        ? `\n\nAlready tried (do not repeat):\n${previous.slice(-6).map((a) => a.sql).join("\n")}`
        : "";

    try {
      const response = await client.messages.create(
        {
          model: MODEL,
          max_tokens: 700,
          system: SYSTEM_PROMPT.replace(/\{schema\}/g, context.schema),
          messages: [{ role: "user", content: schemaDescription + tried }],
        },
        { timeout: TIMEOUT_MS, maxRetries: 0 }
      );

      console.log(
        `[proving-agent] model=${MODEL} input=${response.usage.input_tokens} output=${response.usage.output_tokens}`
      );

      const text = response.content.filter((b) => b.type === "text").map((b) => b.text).join("");
      const match = /\{[\s\S]*\}/.exec(text);
      if (!match) return [];
      const parsed = JSON.parse(match[0]) as { queries?: unknown };
      if (!Array.isArray(parsed.queries)) return [];
      return parsed.queries.filter((q): q is string => typeof q === "string").slice(0, MAX_QUERIES_PER_ROUND);
    } catch (err) {
      console.error("[proving-agent] proposal failed:", err instanceof Error ? err.message : err);
      return [];
    }
  };
}

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
      `We rebuilt ${context.table} and its policies on our own infrastructure — your schema, none of your data — created two synthetic users, and signed in as the first. ` +
      `This query returned ${rows.length} row${rows.length === 1 ? "" : "s"} belonging to the second user:\n\n${sql}\n\n` +
      `That is not a warning derived from reading your policy; it is what came back when we ran it. Your real table has the same policies, so a signed-in user of your app can reach other users' rows the same way. ` +
      `${summariseAttempts(attempts)} ` +
      `The fix is a policy that ties every row to its owner via auth.uid(). We will re-run this exact query afterwards and close the finding only when it returns nothing.`,
    proven: true,
    attempts,
  };
}

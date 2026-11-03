// The action space of the adversarial agent.
//
// Everywhere else in this codebase an LLM decides what to SAY. Here it decides
// what to DO — it composes SQL that gets executed. That is a categorical
// difference, and the boundary cannot be a prompt instruction, because a prompt
// is a request and this needs a refusal.
//
// So the agent proposes and this module disposes. Every statement the model
// produces is validated deterministically before execution, and anything that is
// not a plain read inside the disposable replica schema is rejected outright.
// The model is never told it has been rejected in a way it can negotiate with:
// rejection is terminal for that statement.
//
// The threat this defends against is not primarily a malicious model. It is a
// capable one being helpful in an unwanted direction — reading pg_catalog to
// "understand the schema better", querying auth.users because that is where the
// interesting data is, or calling a function to test something it reasoned its
// way to. Each of those is a sensible next step for an agent exploring a
// database, and each is out of bounds. The rules below assume competence, not
// malice.
//
// Layered under this, unchanged: assertProvingTarget still runs before every
// statement, so even a permitted query cannot reach anything but a verified
// data-less replica.

export class AgentActionRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentActionRefused";
  }
}

/** Statement forms that are never permitted, whatever the context. */
const FORBIDDEN_KEYWORDS =
  /\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|comment|copy|vacuum|analyze|reindex|cluster|refresh|call|do|execute|prepare|listen|notify|begin|commit|rollback|savepoint|set|reset)\b/i;

/**
 * Functions that reach outside the row: filesystem, network, other databases,
 * or the server's own configuration. An agent has legitimate-looking reasons to
 * want several of these.
 */
const FORBIDDEN_FUNCTIONS =
  /\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export|dblink\w*|postgres_fdw\w*|http|http_get|http_post|net\.http\w*|pg_net\w*|pg_sleep|set_config|current_setting|pg_terminate_backend|pg_cancel_backend|query_to_xml|pg_read_server_files)\s*\(/i;

/**
 * Schemas an exploration agent must never touch.
 *
 * `auth` is listed but carved out for its FUNCTIONS. auth.uid()/jwt()/role() are
 * how a policy identifies the caller, so an agent testing policies must be able
 * to call them; auth.users is a table full of real people and is refused. The
 * lookahead is what separates the two, and without it every legitimate policy
 * probe was rejected.
 */
const FORBIDDEN_SCHEMAS =
  /\b(pg_catalog|information_schema|pg_toast|pg_temp\w*|storage|vault|extensions|graphql|realtime|supabase_functions|net)\s*\.|(\bauth\s*\.\s*(?!uid\s*\(|jwt\s*\(|role\s*\(|email\s*\())/i;

/**
 * Schema-qualified TABLE references — only those following FROM or JOIN.
 *
 * Deliberately not "any dotted name". SQL aliases are dotted too (`a.id`,
 * `b.user_id`), and treating those as schema references refused every query
 * using an alias — which is most non-trivial SQL, so the agent could barely
 * express anything. Only the position after FROM/JOIN names a relation.
 */
const QUALIFIED_REF = /\b(?:from|join)\s+([a-z_][a-z0-9_]*)\s*\.\s*([a-z_][a-z0-9_"]*)/gi;

const MAX_STATEMENT_LENGTH = 2_000;

interface AgentActionCheck {
  allowed: boolean;
  reason: string;
}

/**
 * Decides whether one agent-proposed statement may execute.
 *
 * @param sql          the model's proposal
 * @param provingSchema the ONLY schema this statement may reference
 */
export function checkAgentAction(sql: string, provingSchema: string): AgentActionCheck {
  const refuse = (reason: string): AgentActionCheck => ({ allowed: false, reason });

  if (typeof sql !== "string" || sql.trim().length === 0) return refuse("Empty statement.");
  if (sql.length > MAX_STATEMENT_LENGTH) return refuse("Statement is longer than the agent is allowed to send.");

  // Strip string literals before keyword matching, so a table containing the
  // word "update" in a WHERE clause is not mistaken for an UPDATE statement.
  // Comments are removed too: `select 1 -- ; drop table x` is a real trick.
  const stripped = sql
    .replace(/--[^\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/'(?:[^']|'')*'/g, "''");

  // One statement only. A trailing semicolon is fine; a second statement is not.
  const withoutTrailing = stripped.trim().replace(/;+\s*$/, "");
  if (withoutTrailing.includes(";")) return refuse("Only one statement is permitted per action.");

  if (!/^\s*(select|with)\b/i.test(withoutTrailing)) {
    return refuse("Only SELECT is permitted. The agent reads; it never writes.");
  }

  if (FORBIDDEN_KEYWORDS.test(withoutTrailing)) {
    return refuse("Statement contains a write or session-control keyword.");
  }

  if (FORBIDDEN_FUNCTIONS.test(withoutTrailing)) {
    return refuse("Statement calls a function that reaches outside the replica.");
  }

  if (FORBIDDEN_SCHEMAS.test(withoutTrailing)) {
    return refuse("Statement references a system or platform schema.");
  }

  // Every qualified reference must be inside the replica. This is the rule that
  // keeps a query from wandering into the rest of the database it happens to
  // share a connection with.
  if (!/^[a-z_][a-z0-9_]*$/i.test(provingSchema)) {
    return refuse("Invalid proving schema.");
  }
  QUALIFIED_REF.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = QUALIFIED_REF.exec(withoutTrailing)) !== null) {
    const schema = m[1].toLowerCase();
    if (schema !== provingSchema.toLowerCase()) {
      return refuse(`Statement references "${m[1]}", which is outside the replica schema.`);
    }
  }

  // An unqualified table name would resolve through search_path, which we do not
  // control from here. Require the schema explicitly.
  if (!withoutTrailing.toLowerCase().includes(provingSchema.toLowerCase())) {
    return refuse("Statement must reference the replica schema explicitly.");
  }

  return { allowed: true, reason: "Read-only, single statement, inside the replica." };
}

/** Throwing form, for the execution path. */
export function assertAgentAction(sql: string, provingSchema: string): void {
  const check = checkAgentAction(sql, provingSchema);
  if (!check.allowed) throw new AgentActionRefused(check.reason);
}

export interface AgentAttempt {
  sql: string;
  allowed: boolean;
  /** Why it was refused, when it was. */
  reason: string;
  /** Rows returned, when it ran. */
  rows?: unknown[];
  error?: string;
}

/**
 * The evidence trail.
 *
 * Every proposal is recorded whether or not it ran, because "the agent tried to
 * read auth.users and was refused" is exactly the kind of thing that must be
 * visible rather than swallowed — to us while building, and to a customer asking
 * what we did inside their replica.
 */
export function summariseAttempts(attempts: AgentAttempt[]): string {
  const ran = attempts.filter((a) => a.allowed).length;
  const refused = attempts.length - ran;
  const parts = [`${attempts.length} queries proposed`, `${ran} run`];
  if (refused > 0) parts.push(`${refused} refused by the action guard`);
  return parts.join(", ") + ".";
}

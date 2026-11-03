import type { PgPolicy } from "@/lib/deep/policyScan";
import { TENANT_A, TENANT_B } from "./tenantProbe";

// Proving without Supabase Branching.
//
// Branching is Pro-only, and the customer pays for ShipLock and nothing else
// (AGENTS.md). So instead of copying THEIR database, we reconstruct the one
// thing under test — a table and the policies governing it — inside a schema on
// ShipLock's own proving project, seed two synthetic tenants, and ask the same
// question: signed in as tenant A, can I read tenant B's rows?
//
// The doctrine is unchanged and arguably stronger: the customer's database is
// never touched at all, not even a copy of it. Nothing crosses over except the
// policy TEXT we already read.
//
// THE GOVERNING RULE HERE IS DIFFERENT FROM EVERYWHERE ELSE IN THE CODEBASE.
// Normally an uncertain check reports a lower-confidence finding. Not here. A
// replica that is not faithful produces a WRONG PROOF — "we demonstrated your
// app leaks data" about an app that does not — and a wrong proof is far worse
// than no proof, because proof is the thing the customer is asked to trust
// without checking. So replicability is decided by a WHITELIST: if we cannot
// account for every construct in a policy, we refuse to replicate it and fall
// back to the static reasoner's inference, which is honestly labelled as
// inference.

/**
 * Constructs a policy may use and still be faithfully replicable in isolation.
 *
 * Everything here evaluates using only the row itself and the caller's identity.
 * Anything that reaches OUTSIDE the row — another table, a custom function, a
 * sequence — cannot be reproduced without dragging that dependency along, and a
 * policy evaluated without its dependency gives a different answer.
 */
const ALLOWED_CALLS = /\b(auth\.uid|auth\.role|auth\.jwt|current_setting|coalesce|nullif|lower|upper|cast)\s*\(/gi;
const ANY_CALL = /\b([a-z_][\w.]*)\s*\(/gi;

/** Constructs that always mean the policy reaches beyond this row. */
const REACHES_OUT = /\b(select|from|join|exists|lateral|union|intersect|except)\b/i;

interface ReplicabilityVerdict {
  replicable: boolean;
  reason: string;
}

/** Whether a table's policies can be rebuilt faithfully on the replica.
 * Anything it cannot reproduce exactly is refused with a reason. */
export function assessReplicability(policies: PgPolicy[]): ReplicabilityVerdict {
  if (policies.length === 0) {
    return {
      replicable: false,
      reason: "No policies were readable for this table, so there is nothing to reconstruct faithfully.",
    };
  }

  for (const p of policies) {
    for (const expr of [p.qual, p.with_check]) {
      if (!expr) continue;

      if (REACHES_OUT.test(expr)) {
        return {
          replicable: false,
          reason:
            "This policy queries another table, so testing it in isolation would give a different answer than it gives in your database. Reported from static analysis instead, which is labelled as inference rather than proof.",
        };
      }

      // Every function call must be one we can guarantee behaves identically.
      const allowed = new Set<string>();
      let m: RegExpExecArray | null;
      ALLOWED_CALLS.lastIndex = 0;
      while ((m = ALLOWED_CALLS.exec(expr)) !== null) allowed.add(m[0].toLowerCase());

      ANY_CALL.lastIndex = 0;
      while ((m = ANY_CALL.exec(expr)) !== null) {
        const call = m[0].toLowerCase();
        const name = m[1].toLowerCase();
        if (allowed.has(call)) continue;
        // Bare SQL keywords that parse as calls but are not functions.
        if (["in", "not", "and", "or", "any", "all", "array"].includes(name)) continue;
        return {
          replicable: false,
          reason: `This policy calls ${m[1]}(), which we cannot reproduce identically outside your database, so we will not claim to have tested it.`,
        };
      }
    }
  }

  return { replicable: true, reason: "Policy depends only on the row and the caller's identity." };
}

/** Postgres identifier quoting; refuses anything that is not a plain identifier. */
export function ident(name: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`Refusing to build SQL with a non-identifier: ${name}`);
  }
  return `"${name}"`;
}

/** Single-quoted literal, escaped. Used only for values we generate ourselves. */
function lit(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

interface ReplicaPlan {
  schema: string;
  setupSql: string;
  teardownSql: string;
}

/**
 * Builds an isolated schema containing one table and its policies.
 *
 * The table is minimal: the owner column plus a marker. We are testing whether
 * the POLICY lets one tenant see another's row, and every extra column is
 * another chance for a NOT NULL constraint to make setup fail for a reason that
 * has nothing to do with security.
 */
export function buildReplicaPlan(
  runId: string,
  table: string,
  ownerColumn: string,
  policies: PgPolicy[]
): ReplicaPlan {
  const schema = `proving_${runId.replace(/[^a-z0-9]/gi, "").slice(0, 24).toLowerCase()}`;
  const s = ident(schema);
  const t = ident(table);
  const c = ident(ownerColumn);

  const policyStatements = policies
    .map((p, i) => {
      const name = ident(`p_${i}`);
      const cmd = /^(select|insert|update|delete|all)$/i.test(p.cmd ?? "") ? p.cmd.toUpperCase() : "ALL";
      const roles = (p.roles ?? []).filter((r) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(r));
      const to = roles.length > 0 ? ` TO ${roles.map(ident).join(", ")}` : "";
      const using = p.qual ? ` USING (${p.qual})` : "";
      const check = p.with_check ? ` WITH CHECK (${p.with_check})` : "";
      return `create policy ${name} on ${s}.${t} for ${cmd}${to}${using}${check};`;
    })
    .join("\n");

  return {
    schema,
    setupSql: [
      `create schema ${s};`,
      `create table ${s}.${t} (id uuid primary key default gen_random_uuid(), ${c} uuid not null);`,
      `alter table ${s}.${t} enable row level security;`,
      `insert into ${s}.${t} (${c}) values (${lit(TENANT_A)}), (${lit(TENANT_B)});`,
      `grant usage on schema ${s} to authenticated, anon;`,
      `grant select on ${s}.${t} to authenticated, anon;`,
      policyStatements,
    ]
      .filter(Boolean)
      .join("\n"),
    // CASCADE so a partially-built replica still disappears completely.
    teardownSql: `drop schema if exists ${s} cascade;`,
  };
}

/**
 * The leak probe, as one transaction. Used by BOTH arenas — a branch passes
 * `public`, a replica passes its throwaway schema — which is why it is not named
 * for either.
 *
 * `set local` needs a transaction, and the role plus JWT claims must be in place
 * for the same statement that reads the table — that is what makes auth.uid()
 * return our synthetic tenant and the policy evaluate exactly as it would for a
 * signed-in user of the customer's app.
 *
 * Signed in as A, counting B's rows: any result above zero is the policy failing
 * to isolate tenants, demonstrated rather than inferred.
 */
export function buildLeakProbeSql(schema: string, table: string, ownerColumn: string): string {
  const s = ident(schema);
  const t = ident(table);
  const c = ident(ownerColumn);
  const claims = JSON.stringify({ sub: TENANT_A, role: "authenticated" });

  return [
    "begin;",
    "set local role authenticated;",
    `set local request.jwt.claims = ${lit(claims)};`,
    `select count(*)::int as leaked from ${s}.${t} where ${c} = ${lit(TENANT_B)};`,
    "commit;",
  ].join("\n");
}

/**
 * Control probe: signed in as A, count A's OWN rows.
 *
 * Runs before the real probe and must return exactly 1. If it returns 0 the
 * replica is broken — a missing grant, a policy denying everything, claims not
 * applied — and a broken replica would report "no leak" for every table, turning
 * a silent setup failure into a clean bill of health. This is the check that
 * stops the proving ground from confidently proving nothing.
 */
export function buildControlProbeSql(schema: string, table: string, ownerColumn: string): string {
  const s = ident(schema);
  const t = ident(table);
  const c = ident(ownerColumn);
  const claims = JSON.stringify({ sub: TENANT_A, role: "authenticated" });

  return [
    "begin;",
    "set local role authenticated;",
    `set local request.jwt.claims = ${lit(claims)};`,
    `select count(*)::int as visible from ${s}.${t} where ${c} = ${lit(TENANT_A)};`,
    "commit;",
  ].join("\n");
}

interface ReplicaOutcome {
  table: string;
  ownerColumn: string;
  /** Rows of the OTHER tenant visible to tenant A. */
  leakedRows: number;
  /** Tenant A's own rows visible to tenant A. Must be 1 for the run to count. */
  controlRows: number;
  executed: boolean;
  skippedReason?: string;
}

/** True only when the control passed, so the result means something. */
export function isTrustworthy(outcome: ReplicaOutcome): boolean {
  return outcome.executed && outcome.controlRows === 1;
}

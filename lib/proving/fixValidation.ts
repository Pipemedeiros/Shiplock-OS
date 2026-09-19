import type { PgPolicy } from "@/lib/deep/policyScan";
import { ident, buildReplicaPlan } from "./replica";
import { TENANT_A, TENANT_B } from "./tenantProbe";

// Fix pre-validation on the proving ground (CLAUDE.md autonomy doctrine).
//
//   "apply the candidate fix to the branch, re-run the attack (must now fail),
//    re-run the app's known query patterns (must still succeed) — and only then
//    touch production."
//
// This is the half that makes autonomy defensible rather than brave. Detecting a
// permissive policy is worth something; writing a replacement policy and
// applying it to a live database on the strength of our own reasoning is worth
// rather less, because the failure mode is locking every one of a paying
// customer's users out of their own data. For a founder-facing product that is an
// asymmetric bet: five saved minutes against an outage we caused.
//
// The loop removes the bet. Every fix is demonstrated on a replica first, and it
// has to clear THREE gates, in this order:
//
//   1. REPRODUCE   the attack must succeed against the ORIGINAL policy. If it
//                  does not, we never had the vulnerability we claimed, and the
//                  correct action is to withdraw the finding — not to "fix" it.
//   2. CLOSE       the same attack must fail after the fix.
//   3. PRESERVE    legitimate access must still work after the fix.
//
// Gate 3 is the one that exists to stop US. A policy of `USING (false)` passes
// gate 2 perfectly — it closes every attack — and locks out every real user. Any
// validator that only tests whether the attack stopped would wave that through,
// which is precisely how a security tool causes an outage.

export type GateResult = "pass" | "fail" | "not_run";

export interface FixValidation {
  reproduced: GateResult;
  closed: GateResult;
  preserved: GateResult;
  /** Safe to offer for one-click application. True only when all three pass. */
  validated: boolean;
  /** Plain-language account of what happened, shown with the fix. */
  summary: string;
}

export interface FixCandidate {
  /** Human description, used in the summary. */
  description: string;
  /** Policies that replace the originals. */
  policies: PgPolicy[];
}

/**
 * SQL that swaps the original policies for the candidate's, in place.
 *
 * Applied to the replica only. The production path is a separate, explicitly
 * authorised action with a stored inverse — this never writes a customer's
 * database, and the module has no code path that could.
 */
export function buildFixApplySql(
  schema: string,
  table: string,
  originalCount: number,
  candidate: FixCandidate
): string {
  const s = ident(schema);
  const t = ident(table);

  const drops = Array.from({ length: originalCount }, (_, i) => `drop policy if exists ${ident(`p_${i}`)} on ${s}.${t};`);

  const creates = candidate.policies.map((p, i) => {
    const name = ident(`fix_${i}`);
    const cmd = /^(select|insert|update|delete|all)$/i.test(p.cmd ?? "") ? p.cmd.toUpperCase() : "ALL";
    const roles = (p.roles ?? []).filter((r) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(r));
    const to = roles.length > 0 ? ` TO ${roles.map(ident).join(", ")}` : "";
    const using = p.qual ? ` USING (${p.qual})` : "";
    const check = p.with_check ? ` WITH CHECK (${p.with_check})` : "";
    return `create policy ${name} on ${s}.${t} for ${cmd}${to}${using}${check};`;
  });

  return [...drops, ...creates].join("\n");
}

/**
 * One statement returning both gates at once, as tenant A:
 *   leaked  — rows belonging to tenant B that A can see (must be 0 after a fix)
 *   own     — rows belonging to tenant A that A can see (must stay 1)
 *
 * Both are measured in the SAME transaction and the same auth context, so a fix
 * cannot appear to close the attack merely because the session broke.
 */
export function buildGateSql(schema: string, table: string, ownerColumn: string): string {
  const s = ident(schema);
  const t = ident(table);
  const c = ident(ownerColumn);
  const claims = JSON.stringify({ sub: TENANT_A, role: "authenticated" });

  return [
    "begin;",
    "set local role authenticated;",
    `set local request.jwt.claims = '${claims.replace(/'/g, "''")}';`,
    `select`,
    `  (select count(*)::int from ${s}.${t} where ${c} = '${TENANT_B}') as leaked,`,
    `  (select count(*)::int from ${s}.${t} where ${c} = '${TENANT_A}') as own;`,
    "commit;",
  ].join("\n");
}

export interface GateReading {
  leaked: number;
  own: number;
}

/**
 * Judges a validation run from the two readings.
 *
 * @param before reading against the ORIGINAL policies
 * @param after  reading against the candidate fix
 */
export function judgeFix(
  before: GateReading | null,
  after: GateReading | null,
  candidate: FixCandidate
): FixValidation {
  // Gate 1 — did the attack actually work before?
  if (!before) {
    return {
      reproduced: "not_run",
      closed: "not_run",
      preserved: "not_run",
      validated: false,
      summary: "We could not run the check against your current policy, so this fix has not been validated and is not offered for one-click application.",
    };
  }

  if (before.leaked === 0) {
    // Withdraw, do not "fix". Applying a change to close a hole we cannot
    // demonstrate means changing a customer's database on a guess.
    return {
      reproduced: "fail",
      closed: "not_run",
      preserved: "not_run",
      validated: false,
      summary:
        "We could not reproduce the problem against a copy of your policy — signed in as one tenant, we could not read another tenant's rows. That means the finding is probably wrong, so we are not offering a change. We would rather withdraw a finding than alter your database to fix something we cannot demonstrate.",
    };
  }

  if (!after) {
    return {
      reproduced: "pass",
      closed: "not_run",
      preserved: "not_run",
      validated: false,
      summary:
        "We reproduced the problem on a copy, but could not test the proposed fix, so it is not offered for one-click application.",
    };
  }

  const closed = after.leaked === 0;
  const preserved = after.own === 1;

  if (closed && preserved) {
    return {
      reproduced: "pass",
      closed: "pass",
      preserved: "pass",
      validated: true,
      summary:
        `Tested on a copy of your schema with no real data in it. Before the change, signed in as one tenant we could read another tenant's rows — ${before.leaked}. After applying ${candidate.description}, the same attempt returned nothing, and the tenant could still read their own row. ` +
        `So the fix closes the hole without cutting off legitimate access. That second half is the part we check hardest: a policy that blocks everyone would also stop the attack, and would take your users offline with it.`,
    };
  }

  if (closed && !preserved) {
    // The outcome this gate exists for.
    return {
      reproduced: "pass",
      closed: "pass",
      preserved: "fail",
      validated: false,
      summary:
        `This fix would stop the attack but it also stopped legitimate access: on the copy, a tenant could no longer read their OWN rows. Applying it to your database would lock your users out of their own data. ` +
        `We are not offering it. The finding stands and needs a policy that scopes rows to their owner rather than denying them.`,
    };
  }

  return {
    reproduced: "pass",
    closed: "fail",
    preserved: preserved ? "pass" : "fail",
    validated: false,
    summary:
      `This fix did not work. On the copy, one tenant could still read another's rows after applying it (${after.leaked}), so it would have changed your database without closing the hole. Not offered.`,
  };
}

/**
 * The candidate fix for a permissive policy: scope rows to their owner.
 *
 * Deliberately the most conservative correct policy rather than the cleverest —
 * it is going to be validated, but it is also going to be READ by someone
 * deciding whether to trust us, and `auth.uid() = owner` is a policy a founder
 * can verify at a glance.
 */
export function buildOwnershipFix(ownerColumn: string, roles: string[] = ["authenticated"]): FixCandidate {
  // Validated by ident() at SQL build time; checked here too so a bad column
  // never reaches a policy body.
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(ownerColumn)) {
    throw new Error(`Refusing to build a policy with a non-identifier column: ${ownerColumn}`);
  }
  return {
    description: `a policy restricting rows to the signed-in owner (auth.uid() = ${ownerColumn})`,
    policies: [
      {
        schemaname: "public",
        tablename: "",
        policyname: "shiplock_owner_only",
        cmd: "SELECT",
        qual: `auth.uid() = ${ownerColumn}`,
        with_check: null,
        roles,
      },
    ],
  };
}

/** Convenience: the replica plan a validation run needs. */
export function buildValidationPlan(runId: string, table: string, ownerColumn: string, original: PgPolicy[]) {
  return buildReplicaPlan(runId, table, ownerColumn, original);
}

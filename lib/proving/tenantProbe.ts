import type { Severity } from "@/lib/types";

// A4 — tenant isolation, PROVEN rather than inferred.
//
// The graph already detects this statically: an authenticated route with no
// ownership filter over a table whose policies do not narrow it. That inference
// is good, and it is still an inference — it can be wrong when a filter is
// applied somewhere our import walk cannot follow. The proving ground exists to
// settle the question by running the query and seeing what comes back.
//
// WHERE THIS RUNS IS THE WHOLE ETHICAL ARGUMENT. Inside a data-less branch
// seeded with synthetic tenants there is no unethical test: no real user's data
// exists, nothing we break matters, and "read tenant B's rows as tenant A" is a
// factual question about a copy rather than an intrusion. The same statement
// against production would be an attack, which is why lib/proving/guard.ts
// refuses to let it happen and is checked immediately before execution.
//
// The seeded tenants are the point. Two synthetic tenants with rows we created
// means the probe knows EXACTLY what tenant A should be able to see, so the
// result is unambiguous: it either returned rows belonging to tenant B or it did
// not. No heuristics, no confidence score.

export const TENANT_A = "00000000-0000-4000-8000-00000000000a";
export const TENANT_B = "00000000-0000-4000-8000-00000000000b";

/** Column names that plausibly carry the owning user's id. */
const OWNER_COLUMN_CANDIDATES = [
  "user_id",
  "owner_id",
  "account_id",
  "profile_id",
  "created_by",
  "author_id",
  "tenant_id",
  "org_id",
  "organization_id",
];

export function pickOwnerColumn(columns: string[]): string | null {
  const lower = new Set(columns.map((c) => c.toLowerCase()));
  for (const candidate of OWNER_COLUMN_CANDIDATES) {
    if (lower.has(candidate)) return candidate;
  }
  return null;
}

/**
 * Postgres identifier quoting. Every identifier reaching generated SQL passes
 * through here, and anything that is not a plain identifier is refused upstream
 * rather than escaped — the proving ground runs on a throwaway branch, but
 * generating malformed SQL would still make results uninterpretable.
 */
export function quoteIdent(name: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`Refusing to build SQL with a non-identifier: ${name}`);
  }
  return `"${name}"`;
}

export interface SeedPlan {
  table: string;
  ownerColumn: string;
  sql: string;
}

/**
 * Seeds two synthetic tenants into one table.
 *
 * Deliberately minimal: two rows, one per tenant, with only the owner column
 * set. Any other NOT NULL column without a default will cause this to fail, and
 * failing is the correct outcome — a table we cannot seed cleanly is one we
 * cannot draw a conclusion about, and we would rather skip it than report a
 * result we do not understand.
 */
export function buildSeedSql(table: string, ownerColumn: string): SeedPlan {
  const t = quoteIdent(table);
  const c = quoteIdent(ownerColumn);
  return {
    table,
    ownerColumn,
    sql:
      `insert into public.${t} (${c}) values ('${TENANT_A}'), ('${TENANT_B}')`,
  };
}

/**
 * The probe itself: as tenant A, how many rows of tenant B's are visible?
 *
 * Runs with the branch's anon/authenticated role and a JWT claiming tenant A, so
 * it exercises exactly the policies a real signed-in user would hit.
 */
export function buildProbeSql(table: string, ownerColumn: string): string {
  const t = quoteIdent(table);
  const c = quoteIdent(ownerColumn);
  return `select count(*)::int as leaked from public.${t} where ${c} = '${TENANT_B}'`;
}

export interface ProbeOutcome {
  table: string;
  ownerColumn: string;
  /** Rows belonging to the OTHER tenant that were visible. */
  leakedRows: number;
  /** Whether the probe ran at all. */
  executed: boolean;
  /** Why it did not run, when it did not. */
  skippedReason?: string;
}

export interface ProvenFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
  proven: true;
}

/**
 * Turns an outcome into a finding.
 *
 * A probe that did NOT run produces nothing. It does not produce a "possibly
 * vulnerable" — the static graph already covers the inference case, and adding a
 * second, weaker voice saying the same thing would double-count it on the board.
 * The proving ground speaks only when it has proof.
 */
export function interpretProbe(outcome: ProbeOutcome): ProvenFinding | null {
  if (!outcome.executed) return null;
  if (outcome.leakedRows <= 0) return null;

  return {
    id: `proven:tenant_isolation:public.${outcome.table}`,
    severity: "CRITICAL",
    title: `Confirmed: one signed-in user can read another's rows in ${outcome.table}`,
    consequence:
      `We copied your database structure into a temporary branch — schema, policies and configuration, with none of your data — created two synthetic users in it, and signed in as the first. ` +
      `Querying ${outcome.table} returned ${outcome.leakedRows} row${outcome.leakedRows === 1 ? "" : "s"} belonging to the second user. ` +
      `This is not a warning based on reading your policies; it is what actually happened when we tried. Your real ${outcome.table} table has the same policies, so a signed-in user of your app can read other users' rows there too. ` +
      `The fix is a policy on ${outcome.table} that compares the owner column (${outcome.ownerColumn}) to auth.uid(), so the database enforces the boundary regardless of what any endpoint forgets to filter. ` +
      `Once you have applied it we will re-run this same probe and confirm it now returns nothing — you will see the finding close on evidence rather than on our say-so.`,
    proven: true,
  };
}

/**
 * Which tables are worth probing, given what the graph already suspects.
 *
 * The proving ground costs real money per run (~$0.013/hour for the branch) and
 * takes minutes, so it does not sweep everything. It tests what the reasoner
 * flagged, which is what makes the two halves complement rather than duplicate
 * each other: the graph decides WHAT to test, the proving ground decides whether
 * it is TRUE.
 */
export function selectTablesToProbe(
  suspectedTables: string[],
  schema: Map<string, string[]>,
  limit = 5
): { table: string; ownerColumn: string }[] {
  const out: { table: string; ownerColumn: string }[] = [];
  for (const qualified of suspectedTables) {
    const table = qualified.replace(/^public\./, "");
    const columns = schema.get(table) ?? schema.get(qualified);
    if (!columns) continue;
    const ownerColumn = pickOwnerColumn(columns);
    // No owner column means there is no per-tenant boundary to test. Skipped
    // rather than guessed: probing on the wrong column would produce a
    // confident, meaningless answer.
    if (!ownerColumn) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) continue;
    out.push({ table, ownerColumn });
    if (out.length >= limit) break;
  }
  return out;
}

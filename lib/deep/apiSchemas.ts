import { z } from "zod";

// Shape validation for everything an external API hands a collector.
//
// WHY THIS EXISTS, precisely. Every fetcher used to end in `as T[]` — a cast,
// which is a promise to the compiler and nothing at all at runtime. The failure
// that produces is not a crash, it is SILENCE: if Supabase renames `qual`, the
// policy rows still arrive, `isPermissiveExpression(undefined)` returns false,
// no permissive policy is found, no attack path fires, and the dashboard says
// "no correlated findings" about a database with a `USING (true)` policy on it.
//
// That is the worst failure this product can have. Every other guard in the
// codebase points at false POSITIVES — don't claim a leak you didn't reproduce,
// don't say RLS is off when you only saw a permissive policy. This one points
// the other way, at a false negative that is indistinguishable from good news
// and unfalsifiable from outside. AGENTS.md prohibits reading silence as clean;
// silence cannot mean "our parser fell off".
//
// It has happened here before: two advisor lint slugs in the old allow-list did
// not exist, silently discarding the `USING (true)` finding the product story is
// built on. `normaliseLintName` fixed that instance; this closes the class.
//
// TWO RULES FOR EVERY SCHEMA BELOW:
//
// 1. VALIDATE WHAT WE DEPEND ON, IGNORE THE REST. Zod strips unknown keys by
//    default and that is deliberate — a provider ADDING a field is not a
//    breakage, and failing on it would make us fragile in the direction that
//    costs the customer their scan for no reason. We fail only when a field the
//    reasoner actually reads is missing or the wrong type.
//
// 2. ERRORS NEVER CARRY VALUES. Zod's default messages embed the received data,
//    and this data is the customer's schema — table names, column names, and in
//    some fetchers row counts. "ShipLock never reads your users' data" is
//    customer-facing copy, so `describeIssues` reports the PATH and the EXPECTED
//    type only. A log line that helps us debug at the cost of leaking their
//    schema into our log aggregator is not a trade we get to make.

/**
 * Thrown when an API's response does not match what the collector needs.
 *
 * Deliberately an error rather than a fallback to `[]`. The empty array is what
 * made this class of bug invisible: it is indistinguishable from a genuinely
 * clean result. Throwing routes this into the collector registry's `failed`
 * status, where the existing all-collectors-failed guard already refuses to
 * write a snapshot that would read as "everything got fixed".
 */
export class CollectorShapeError extends Error {
  constructor(
    /** Which fetch produced it, e.g. "fetchPolicies". */
    readonly source: string,
    /** Field paths and expected types. NEVER received values. */
    readonly issues: string[],
    /** How many rows failed, when the payload was a list. */
    readonly failedRows?: number
  ) {
    super(
      `${source}: response did not match the expected shape` +
        (failedRows !== undefined ? ` (${failedRows} row(s))` : "") +
        (issues.length > 0 ? ` — ${issues.join("; ")}` : "")
    );
    this.name = "CollectorShapeError";
  }
}

/**
 * Field paths and expected types, with received values stripped.
 *
 * Zod's `issue.message` interpolates the received value ("expected string,
 * received number" is fine; "invalid literal, received 'customers'" is not), so
 * the message is rebuilt from structured fields rather than reused.
 */
export function describeIssues(error: z.ZodError, limit = 5): string[] {
  const seen = new Set<string>();
  for (const issue of error.issues) {
    const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
    // `expected` is present on type mismatches; other codes carry only a code,
    // which is safe because it names the rule, not the data.
    const expected = "expected" in issue ? String(issue.expected) : issue.code;
    seen.add(`${path}: expected ${expected}`);
    if (seen.size >= limit) break;
  }
  return [...seen];
}

/**
 * Parse a list payload, or throw.
 *
 * ALL-OR-NOTHING, and that is the considered choice. A single malformed row
 * among many almost never means one bad record — it means the contract moved,
 * and the rows that still parse are the ones whose fields happen to overlap the
 * old shape. Keeping those would hand the reasoner a silently partial view of
 * the customer's database, which is the same false-negative failure in a
 * smaller package. Better to fail the layer and say so.
 */
export function parseRows<T>(source: string, schema: z.ZodType<T>, json: unknown): T[] {
  if (!Array.isArray(json)) {
    throw new CollectorShapeError(source, [`(root): expected array, got ${typeName(json)}`]);
  }

  const out: T[] = [];
  const issues: string[] = [];
  let failed = 0;

  for (const row of json) {
    const result = schema.safeParse(row);
    if (result.success) {
      out.push(result.data);
      continue;
    }
    failed += 1;
    if (issues.length < 5) issues.push(...describeIssues(result.error, 5 - issues.length));
  }

  if (failed > 0) throw new CollectorShapeError(source, [...new Set(issues)], failed);
  return out;
}

/** Parse a single object payload, or throw. */
export function parseObject<T>(source: string, schema: z.ZodType<T>, json: unknown): T {
  const result = schema.safeParse(json);
  if (!result.success) throw new CollectorShapeError(source, describeIssues(result.error));
  return result.data;
}

/** Type name for an error message, without revealing the value. */
function typeName(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

// ── Shared field shapes ────────────────────────────────────────────────────

/**
 * Postgres `name[]` columns, which arrive as a real array over some transports
 * and as the literal string "{anon,authenticated}" over others.
 *
 * Normalised here rather than at each call site, because a `roles` value that
 * silently became a string would make `grantedRoles` empty and quietly weaken
 * every finding that names who can reach a table.
 */
export const PgRoleArray = z
  .union([z.array(z.string()), z.string(), z.null()])
  .transform((v): string[] => {
    if (Array.isArray(v)) return v;
    if (typeof v === "string") {
      return v
        .replace(/^\{|\}$/g, "")
        .split(",")
        .filter(Boolean);
    }
    return [];
  });

/** Postgres counts arrive as bigint strings over JSON transports. */
export const PgCount = z.union([z.number(), z.string()]).transform((v) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
});

// ── Per-endpoint schemas ───────────────────────────────────────────────────

/**
 * A row from `pg_policies`.
 *
 * `qual` and `with_check` are nullable for real reasons, not defensiveness: an
 * INSERT-only policy has no USING expression, and a SELECT-only policy has no
 * WITH CHECK. Making them required would fail valid databases; making them
 * optional-and-missing is what let a renamed field read as "no restriction".
 * `.nullable()` without `.optional()` is the distinction that matters — the key
 * must be PRESENT, and may be null.
 */
export const PgPolicyRow = z.object({
  schemaname: z.string(),
  tablename: z.string(),
  policyname: z.string(),
  cmd: z.string(),
  qual: z.string().nullable(),
  with_check: z.string().nullable(),
  roles: PgRoleArray,
});

/**
 * A Supabase security advisor lint.
 *
 * Everything is optional here on purpose, and this is the one schema that is
 * deliberately permissive: the advisor payload's shape genuinely varies by
 * Supabase version, and `mapAdvisors` already skips entries without a `name`.
 * Validating it strictly would turn a cosmetic upstream change into a failed
 * scan. What we DO enforce is that it is an object with the right field types
 * when present, so a wholesale change of the endpoint still fails loudly.
 */
export const SupabaseAdvisorRow = z.object({
  name: z.string().optional(),
  title: z.string().optional(),
  level: z.string().optional(),
  description: z.string().optional(),
  detail: z.string().optional(),
  cache_key: z.string().optional(),
  remediation: z.string().optional(),
  metadata: z
    .object({
      name: z.string().optional(),
      schema: z.string().optional(),
      type: z.string().optional(),
    })
    .nullable()
    .optional(),
});

/**
 * The auth configuration object.
 *
 * Passthrough, because `scanAuthPolicy` reads a wide and growing set of keys and
 * enumerating them here would mean two lists drifting apart. The assertion that
 * matters is that this is an OBJECT: `readAuthPosture` reads `disable_signup`
 * with a `typeof === "boolean"` guard and correctly yields `null` for anything
 * else, so a missing key already degrades to "unknown" rather than to a wrong
 * answer. An array or a string here, though, means the endpoint changed.
 */
export const SupabaseAuthConfigObject = z.looseObject({});

export const SchemaColumnRow = z.object({
  table_name: z.string(),
  column_name: z.string(),
});

export const RowCountRow = z.object({
  table_name: z.string(),
  n: PgCount,
});

export const ColumnGrantRow = z.object({
  grantee: z.string(),
  table_name: z.string(),
  column_name: z.string(),
  privilege_type: z.string(),
});

/** RLS state per table, read from the catalogue by the direct-Postgres path. */
export const RlsStateRow = z.object({
  name: z.string(),
  rls_enabled: z.boolean(),
});

// ── Capability / storage / realtime rows ───────────────────────────────────
//
// These feed fetchers whose `attempt` helper already returns `undefined` on
// failure rather than `[]` — the honest "we could not look" that the rest of
// this file is about restoring elsewhere. Schemas make a SHAPE change reach that
// same `undefined` instead of producing rows whose fields are all absent, which
// would read as "the extension has no name" rather than "we could not check".

export const ExtensionRow = z.object({ name: z.string(), schema: z.string() });

export const NetworkGrantRow = z.object({
  schema: z.string(),
  name: z.string(),
  grantee: z.string(),
});

export const CronJobRow = z.object({
  name: z.string().nullable(),
  schedule: z.string(),
  runs_as: z.string(),
  command: z.string(),
});

export const ForeignServerRow = z.object({ server: z.string(), wrapper: z.string() });

export const BucketRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  public: z.boolean(),
  file_size_limit: z.number().nullable(),
  allowed_mime_types: z.array(z.string()).nullable(),
});

export const StoragePolicyRowSchema = z.object({
  name: z.string(),
  cmd: z.string(),
  qual: z.string(),
  roles: z.string(),
});

export const RealtimeTableRowSchema = z.object({
  schema: z.string(),
  name: z.string(),
  rls_enabled: z.boolean(),
  policy_count: PgCount,
});

export const AuthHookRowSchema = z.object({
  schema: z.string(),
  name: z.string(),
  security_definer: z.boolean(),
  config: z.string(),
});

// The two rows that decide whether we will hold a customer's connection string
// at all. Both were previously read with optional chaining over an unvalidated
// row — `role?.rolsuper`, `Number(writable?.count ?? 0)` — which is falsy and
// zero respectively when the column is absent. A renamed catalogue column would
// therefore have APPROVED a superuser or a writable role. These are the two
// schemas where a parse failure must block rather than degrade.

export const RoleFlagsRow = z.object({
  rolsuper: z.boolean(),
  rolbypassrls: z.boolean(),
});

export const WriteGrantCountRow = z.object({ count: PgCount });

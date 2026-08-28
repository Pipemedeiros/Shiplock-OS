import type { ArchiveFile } from "@/lib/deep/repoArchive";

/**
 * Table names, read from whatever the repository uses to declare them.
 *
 * Three sources, because the ICP does not agree on one: Drizzle schema files,
 * Prisma models, and raw SQL migrations. A project using something else yields
 * an empty set, which the caller reports as "no schema identified" rather than
 * as "this application has no tables".
 */

const DRIZZLE_TABLE = /(?:pgTable|mysqlTable|sqliteTable)\s*\(\s*["'`]([a-zA-Z0-9_]+)["'`]/g;
const PRISMA_MODEL = /^\s*model\s+([A-Za-z0-9_]+)\s*\{/gm;
const SQL_CREATE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?([a-zA-Z0-9_]+)"?/gi;
const SUPABASE_FROM = /\.from\(\s*["'`]([a-zA-Z0-9_]+)["'`]\s*\)/g;

/**
 * Files that describe code rather than being it.
 *
 * Test fixtures are full of `create table t (...)` and `.from("a")`. Dogfooding
 * this against ShipLock's own repository produced tables called "a", "b", "t",
 * "one", "two", "three" and "AS" -- all of them from test strings. A schema
 * inventory that includes invented tables is worse than a short one: the agent
 * cites them, and the guard cannot tell a real table it has never seen from a
 * fake one it has.
 */
const NOT_APPLICATION_CODE = /(^|\/)(.*\.(test|spec)\.[cm]?[jt]sx?|__tests__|__mocks__|fixtures?)($|\/)/;

/** SQL keywords a greedy CREATE TABLE match picks up as if they were names. */
const SQL_NOISE = new Set([
  "as", "if", "not", "exists", "table", "public", "temp", "temporary", "unlogged", "select", "from",
]);

/** Rejects names that are noise rather than schema. */
function plausibleTable(name: string): boolean {
  if (name.length < 3) return false;
  if (SQL_NOISE.has(name.toLowerCase())) return false;
  // A name that is only digits, or a single repeated character, is a fixture.
  return /[a-z]/i.test(name) && !/^\d+$/.test(name);
}

/** Prisma models are PascalCase; the table they create is conventionally snake. */
function pascalToSnake(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function collect(re: RegExp, text: string, out: Set<string>, transform?: (s: string) => string): void {
  // A fresh lastIndex each time: these are module-level /g regexes and sharing
  // state between files would silently skip matches in every second file.
  re.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const name = transform ? transform(match[1]) : match[1];
    if (name && plausibleTable(name)) out.add(name);
  }
}

export function extractTables(files: ArchiveFile[]): string[] {
  const tables = new Set<string>();

  for (const file of files) {
    if (NOT_APPLICATION_CODE.test(file.path)) continue;
    if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) {
      collect(DRIZZLE_TABLE, file.content, tables);
      collect(SUPABASE_FROM, file.content, tables);
    }
    if (file.path.endsWith(".prisma")) {
      collect(PRISMA_MODEL, file.content, tables, pascalToSnake);
    }
    if (file.path.endsWith(".sql")) {
      collect(SQL_CREATE, file.content, tables);
    }
  }

  return [...tables].sort();
}

// Column names, for reading the ownership boundary rather than the table list.
// Deliberately loose: it collects candidate identifiers from schema-ish files
// and lets lib/agent/domain.ts decide which of them mean anything. A column
// name is a hint about intent, never a finding.
const COLUMN_PATTERNS = [
  // drizzle: workspaceId: uuid("workspace_id")
  /\b[A-Za-z_]\w*\s*:\s*\w+\(\s*["'`]([a-z][a-z0-9_]*)["'`]/g,
  // sql: workspace_id uuid not null
  /^\s*["`]?([a-z][a-z0-9_]*)["`]?\s+(uuid|text|varchar|int|integer|bigint|serial|boolean|timestamp|jsonb|numeric)/gim,
  // prisma: workspaceId String
  /^\s*([a-zA-Z][a-zA-Z0-9_]*)\s+(String|Int|BigInt|Boolean|DateTime|Json|Float|Decimal)\b/gm,
];

// Where a column DEFINITION can legitimately live. Deliberately narrow.
//
// The first version accepted any file whose path or content looked schema-ish,
// and reading this repository it picked `workspace_id` out of a page of mock
// dashboard data and out of domain.ts's own list of tenant-key candidates.
// ShipLock is separated by user_id, so the audit was told the wrong boundary —
// and the boundary is the single most important thing the model is told.
//
// A name mentioned anywhere is not a schema. A name being DEFINED is.
const SCHEMA_FILE = /(^|\/)(migrations?|schema|models?|db|prisma)(\/|\.)|\.sql$|\.prisma$/i;
const DEFINES_TABLE = /pgTable|mysqlTable|sqliteTable|createTable|CREATE\s+TABLE/i;

// Mock data, design prototypes and fixtures describe an imaginary product.
// Reading them tells us about the mock, not the customer.
const NOT_REAL_SCHEMA = /(^|\/)(proto|proto-v3|proto-codex|design|__mocks__|__fixtures__|fixtures?|mocks?|examples?)(\/|$)|(^|\/)data\.[cm]?[jt]s$/i;

/**
 * Source with comments removed.
 *
 * A column named in a comment is not a column. This repository proved the point
 * on itself: schema.ts's own explanation of the tenant-key problem contains the
 * words workspace_id, and reading it back made ShipLock look like a workspace
 * product. The same mistake reads a customer's commented-out old schema as
 * their current one.
 */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[^]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/^\s*(--|#)[^\n]*/gm, "");
}

/** Candidate column names across the repository's schema files. */
export function extractColumns(files: ArchiveFile[]): string[] {
  const columns = new Set<string>();

  for (const file of files) {
    if (NOT_APPLICATION_CODE.test(file.path)) continue;
    if (NOT_REAL_SCHEMA.test(file.path)) continue;
    // Either the file is in a schema location, or it actually defines a table.
    // Naming a table is not the same as declaring one.
    if (!SCHEMA_FILE.test(file.path) && !DEFINES_TABLE.test(file.content)) continue;

    const source = withoutComments(file.content);

    for (const pattern of COLUMN_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(source)) !== null) {
        const name = pascalToSnake(match[1]);
        if (name.length > 1 && name.length < 60) columns.add(name);
      }
    }
  }

  return [...columns].sort();
}

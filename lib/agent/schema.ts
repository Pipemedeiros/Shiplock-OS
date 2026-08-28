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
    if (name) out.add(name);
  }
}

export function extractTables(files: ArchiveFile[]): string[] {
  const tables = new Set<string>();

  for (const file of files) {
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

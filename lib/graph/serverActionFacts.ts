import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport, stripComments } from "@/lib/deep/clientExposure";
import { resolveViaTsconfigPaths } from "./tsconfigPaths";
import { STRONG_USER_AUTH_RE } from "./routeInventory";
import { findServerActionEntries } from "./serverActions";

/**
 * Facts for server actions the browser can call (Step 7E-2), the action
 * counterpart of RouteFact's identity, data and ownership fields.
 *
 * Identity comes from where it is resolved: for an action built on an action
 * client (`authActionClient.inputSchema(s).action(fn)`, next-safe-action), the
 * client's `.use(...)` middleware chain; for a plain exported function, its own
 * body. A client that cannot be resolved is UNREADABLE, never anonymous.
 * Ownership is read in the action body: a `where` narrowed by identity the
 * middleware put in `ctx` (for example `workspace.id` from `const { workspace }
 * = ctx`) or by the session's user id.
 */
export type ServerActionFact = {
  file: string; name: string; client: string | null; importedBy: string[];
  identityReadable: boolean; identityGap: string | null; authenticated: boolean;
  tables: string[]; ownershipReadable: boolean; ownershipFiltered: boolean;
};

// Action-client middleware may load the caller with an app's own loader
// (`getCurrentUser()`), which the route pattern does not list. Accepted only
// together with a refusal in the same middleware, so a loader that tolerates
// a missing user does not read as a gate. (Tuned on corpus-d, unlabeled
// development data, 2026-09-24.)
const MIDDLEWARE_LOADER = /\b(?:get(?:Current|Authenticated|Server)?(?:User|Session)\w*|require(?:User|Session|Auth)\w*)\s*\(/;
const REFUSAL = /\bthrow\b|\bredirect\s*\(|\bunauthorized\b|\bnotFound\s*\(/i;
const middlewareAuthenticates = (text: string) =>
  STRONG_USER_AUTH_RE.test(text) || (MIDDLEWARE_LOADER.test(text) && REFUSAL.test(text));

const PRISMA = /\bprisma\.(\w+)\.(?:find\w*|create\w*|update\w*|upsert|delete\w*|count|aggregate|groupBy)\s*\(/g;
const IMPORT = /import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']/g;

function exportSegment(content: string, name: string): string | null {
  const start = content.search(new RegExp(`export\\s+(?:async\\s+)?(?:function\\s+${name}\\b|const\\s+${name}\\s*=)`));
  if (start < 0) return null;
  const next = content.slice(start + 1).search(/\nexport\s/);
  return content.slice(start, next < 0 ? undefined : start + 1 + next);
}

function importSource(content: string, identifier: string): string | null {
  for (const [, names, spec] of content.matchAll(IMPORT)) {
    if (names.split(",").some((n) => n.trim().split(/\s+as\s+/).pop()?.trim() === identifier)) return spec;
  }
  return null;
}

/** The middleware text of an action client, following `.use(` parents in its file. */
function clientMiddleware(clientName: string, file: RepoFile, byPath: Map<string, RepoFile>, depth = 0): string | null {
  if (depth > 4) return null;
  let content = stripComments(file.content);
  let host = file;
  let definition = exportSegment(content, clientName) ?? content.match(new RegExp(`const\\s+${clientName}\\s*=[\\s\\S]*?(?=\\n(?:export\\s+)?const\\s|$)`))?.[0] ?? null;
  if (!definition) {
    const spec = importSource(content, clientName);
    if (!spec) return null;
    const target = resolveImport(file.path, spec, byPath) ?? resolveViaTsconfigPaths(file.path, spec, byPath);
    const targetFile = target ? byPath.get(target) : undefined;
    if (!targetFile) return null;
    host = targetFile;
    content = stripComments(targetFile.content);
    definition = exportSegment(content, clientName);
    if (!definition) return null;
  }
  if (/createSafeActionClient\s*\(/.test(definition) && !/\.use\s*\(/.test(definition)) return definition;
  const parent = definition.match(/=\s*(\w+)\s*\.\s*use\s*\(/)?.[1];
  if (!parent) return /\.use\s*\(/.test(definition) ? definition : null;
  const parentText = clientMiddleware(parent, host, byPath, depth + 1);
  return parentText === null ? null : `${parentText}\n${definition}`;
}

export function analyzeServerActions(files: RepoFile[]): ServerActionFact[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  return findServerActionEntries(files).map((entry) => {
    const file = byPath.get(entry.file)!;
    const segment = stripComments(exportSegment(file.content, entry.name) ?? "");
    const client = segment.match(new RegExp(`const\\s+${entry.name}\\s*=\\s*(\\w+)[\\s\\S]*?\\.\\s*action\\s*\\(`))?.[1] ?? null;
    let identityReadable = true, identityGap: string | null = null, authenticated: boolean;
    let identitySource = segment;
    if (client) {
      const middleware = clientMiddleware(client, file, byPath);
      if (middleware === null) {
        identityReadable = false;
        identityGap = `the action client ${client} could not be resolved`;
        authenticated = false;
      } else {
        identitySource = middleware;
        authenticated = middlewareAuthenticates(middleware);
      }
    } else {
      authenticated = STRONG_USER_AUTH_RE.test(segment);
    }
    const tables = [...new Set([...segment.matchAll(PRISMA)].map((m) => m[1]))].sort();
    // Identity values a where clause may narrow by: ctx keys the middleware
    // injects (destructured or accessed), and the session's user id.
    const ctxKeys = [...identitySource.matchAll(/ctx\s*:\s*\{([^}]*)\}/g)].flatMap((m) => m[1].split(",").map((k) => k.split(":")[0].trim()).filter(Boolean));
    const destructured = [...segment.matchAll(/const\s*\{([^}]*)\}\s*=\s*ctx\b/g)].flatMap((m) => m[1].split(",").map((k) => k.trim().split(/\s*:\s*/).pop()!));
    const identityNames = [...new Set([...ctxKeys, ...destructured])].filter((k) => /^\w+$/.test(k));
    const narrowedBy = new RegExp(`where\\s*:\\s*\\{[^}]*(?:\\bctx\\.\\w+|${identityNames.map((k) => `\\b${k}\\.id\\b|\\b${k}Id\\b`).join("|") || "(?!)"}|session\\.user\\.id|userId\\s*:\\s*session)`);
    const ownershipFiltered = tables.length > 0 && narrowedBy.test(segment);
    return { file: entry.file, name: entry.name, client, importedBy: entry.importedBy, identityReadable, identityGap,
      authenticated, tables, ownershipReadable: identityReadable, ownershipFiltered };
  }).sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
}

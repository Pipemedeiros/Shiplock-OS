import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport, stripComments } from "@/lib/deep/clientExposure";
import { resolveViaTsconfigPaths } from "./tsconfigPaths";
import { ADMIN_GATE_RE, executedCheckGap, extractTables, STRONG_USER_AUTH_RE, type RouteFact } from "./routeInventory";
import { traceExecutedSources } from "./callPath";
import { findServerActionEntries } from "./serverActions";

/**
 * Facts for server actions the browser can call, the action
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
type ServerActionFact = {
  file: string; name: string; client: string | null; importedBy: string[];
  identityReadable: boolean; identityGap: string | null; authenticated: boolean;
  tables: string[]; ownershipReadable: boolean; ownershipFiltered: boolean; ownershipGap: string | null;
};

/** Why an entry's ownership could not be read, in the words a finding quotes
 * (shared by actions and tRPC procedures). Null only when it was read. */
export function ownershipGapFor(o: { ownershipReadable: boolean; identityGap: string | null; tables: string[];
  wheres: number; adminGate?: string | null }): string | null {
  if (o.ownershipReadable) return null;
  if (o.identityGap) return o.identityGap;
  if (o.adminGate) return `the caller is admitted by role in ${o.adminGate}, so the query is deliberately not narrowed to one tenant`;
  if (o.tables.length === 0) return "it reaches no table we could read";
  if (o.wheres === 0) return "we read no where clause on the tables it reaches";
  // Readable identity, tables and where clauses leave only the helper hand-off.
  return "it hands the caller's identity to a helper whose query we do not read";
}

// Action-client middleware may load the caller with an app's own loader
// (`getCurrentUser()`), which the route pattern does not list. Accepted only
// together with a refusal in the same middleware, so a loader that tolerates
// a missing user does not read as a gate. (Tuned on corpus-d, unlabeled
// development data, 2026-09-24.)
const MIDDLEWARE_LOADER = /\b(?:get(?:Current|Authenticated|Server)?(?:User|Session)\w*|require(?:User|Session|Auth)\w*)\s*\(/;
const REFUSAL = /\bthrow\b|\bredirect\s*\(|\bunauthorized\b|\bnotFound\s*\(/i;
/** Whether middleware text signs callers in and refuses those without a
 * session. */
export const middlewareAuthenticates = (text: string) =>
  STRONG_USER_AUTH_RE.test(text) || (MIDDLEWARE_LOADER.test(text) && REFUSAL.test(text));

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

export const NOT_HELPERS = new Set(["action", "inputSchema", "schema", "metadata", "if", "for", "while", "switch", "catch", "return",
  "async", "function", "String", "Number", "Boolean", "Array", "Object", "JSON", "Promise", "Error"]);

/** Every call in the text with its own argument text (bracket counting, so
 * nested calls are each seen). Prisma calls are skipped: their where clauses
 * are judged directly. */
export function calls(text: string): { callee: string; args: string }[] {
  const out: { callee: string; args: string }[] = [];
  for (const m of text.matchAll(/(?<![.\w])(\w+)\s*\(|\.(\w+)\s*\(/g)) {
    const callee = m[1] ?? m[2];
    if (/^prisma$/.test(callee) || /\bprisma\.\w+\.$/.test(text.slice(Math.max(0, (m.index ?? 0) - 40), m.index))) continue;
    let depth = 0, end = (m.index ?? 0) + m[0].length;
    for (let i = end - 1; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")" && --depth === 0) { end = i; break; }
    }
    out.push({ callee, args: text.slice((m.index ?? 0) + m[0].length, end) });
  }
  return out;
}

// Query-builder calls that carry ctx into a where clause rather than to a
// helper that may narrow on its own (Drizzle operators and chain methods).
export const QUERY_BUILDER = new Set(["where", "and", "or", "not", "eq", "ne", "inArray", "notInArray", "isNull", "isNotNull",
  "gt", "gte", "lt", "lte", "like", "ilike", "select", "from", "insert", "update", "delete", "set", "values",
  "returning", "limit", "offset", "orderBy", "findFirst", "findMany", "leftJoin", "innerJoin", "sql", "Number", "toString", "transaction"]);

/** Text of a balanced (...) or {...} starting at `open`. */
function balanced(text: string, open: number): string {
  const close = text[open] === "(" ? ")" : "}";
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === text[open]) depth++;
    else if (text[i] === close && --depth === 0) return text.slice(open, i + 1);
  }
  return text.slice(open);
}

/** Every where clause in the text: Prisma `where: {...}` and Drizzle `.where(...)`. */
export function whereClauses(text: string): string[] {
  return [...text.matchAll(/\bwhere\s*:\s*\{|\.where\s*\(/g)].map((m) => balanced(text, (m.index ?? 0) + m[0].length - 1));
}

/** Route facts for exported server actions: who may call them, what they write,
 * and whether the write is scoped to the caller. */
export function analyzeServerActions(files: RepoFile[]): ServerActionFact[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  return findServerActionEntries(files).map((entry) => {
    const file = byPath.get(entry.file)!;
    const segment = stripComments(exportSegment(file.content, entry.name) ?? "");
    const client = segment.match(new RegExp(`const\\s+${entry.name}\\s*=\\s*(\\w+)[\\s\\S]*?\\.\\s*action\\s*\\(`))?.[1] ?? null;
    let identityReadable = true, identityGap: string | null = null, authenticated: boolean;
    let identitySource = segment;
    // Where an admin test runs on the action's path (its client's
    // middleware, or the calls it makes), scope is unread by design.
    let adminGate: string | null = null;
    if (client) {
      const middleware = clientMiddleware(client, file, byPath);
      if (middleware === null) {
        identityReadable = false;
        identityGap = `the action client ${client} could not be resolved`;
        authenticated = false;
      } else {
        identitySource = middleware;
        authenticated = middlewareAuthenticates(middleware);
        if (ADMIN_GATE_RE.test(middleware)) adminGate = `the action client ${client}`;
      }
    } else {
      // A plain action is read on the path it runs, like a route: a
      // session resolved in a helper it calls counts, and a credential check
      // we cannot classify anywhere on that path makes it unreadable, never
      // anonymous. Untraceable (parse failure, budget): its own text, as before.
      const trace = traceExecutedSources(file, byPath, { roots: [entry.name],
        isIdentityCall: (callee) => STRONG_USER_AUTH_RE.test(`${callee}(`) });
      const executed = trace ? trace.sources : [{ path: entry.file, src: segment }];
      authenticated = executed.some((s) => STRONG_USER_AUTH_RE.test(s.src));
      adminGate = executed.find((s) => ADMIN_GATE_RE.test(s.src))?.path ?? null;
      if (!authenticated) {
        identityGap = trace?.conditionalIdentityPaths.length
          ? `a session is resolved in ${trace.conditionalIdentityPaths[0]} only when an option says so, and we could not read which option this action sets`
          : executedCheckGap(executed);
        identityReadable = identityGap === null;
      }
    }
    // Same table reading as routes and procedures: Drizzle writes and
    // Prisma transaction clients included.
    const tables = extractTables(segment);
    // Identity values a where clause may narrow by: ctx keys the middleware
    // injects (destructured or accessed), and the session's user id.
    const ctxKeys = [...identitySource.matchAll(/ctx\s*:\s*\{([^}]*)\}/g)].flatMap((m) => m[1].split(",").map((k) => k.split(":")[0].trim()).filter(Boolean));
    const destructured = [...segment.matchAll(/const\s*\{([^}]*)\}\s*=\s*ctx\b/g)].flatMap((m) => m[1].split(",").map((k) => k.trim().split(/\s*:\s*/).pop()!));
    const identityNames = [...new Set([...ctxKeys, ...destructured])].filter((k) => /^\w+$/.test(k));
    const narrowedBy = new RegExp(`\\bctx\\.\\w+|${identityNames.map((k) => `\\b${k}\\.id\\b|\\b${k}Id\\b`).join("|") || "(?!)"}|session\\.user\\.id|userId\\s*:\\s*session`);
    const wheres = whereClauses(segment);
    const ownershipFiltered = tables.length > 0 && wheres.some((w) => narrowedBy.test(w));
    // "Not filtered" is claimed only when we read the action's own where
    // clauses and it does not hand the caller's identity to a helper that
    // may do the narrowing. Otherwise ownership is unreadable, never assumed.
    const identityRef = new RegExp(`\\bctx\\.\\w+${identityNames.map((k) => `|\\b${k}\\b`).join("")}`);
    const handedToHelper = calls(segment)
      .some((call) => !NOT_HELPERS.has(call.callee) && !QUERY_BUILDER.has(call.callee) && identityRef.test(call.args));
    const judgedWhere = wheres.length > 0;
    const ownershipReadable = identityReadable && (ownershipFiltered || (!adminGate && tables.length > 0 && judgedWhere && !handedToHelper));
    return { file: entry.file, name: entry.name, client, importedBy: entry.importedBy, identityReadable, identityGap,
      authenticated, tables, ownershipReadable, ownershipFiltered,
      ownershipGap: ownershipGapFor({ ownershipReadable, identityGap, tables, wheres: wheres.length, adminGate }) };
  }).sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
}

/**
 * Entry server actions as route facts, so the audit ranks, prompts and
 * guards them exactly like route handlers. The path `action:<file>#<name>` is
 * what a hypothesis cites. Service-role, machine-gate and data readability are
 * not separately read for actions: they carry the identity readability, so an
 * unreadable action is unreadable everywhere and never ranks as anonymous.
 */
export function serverActionRoutes(files: RepoFile[]): RouteFact[] {
  return analyzeServerActions(files).map((a) => ({
    path: `action:${a.file}#${a.name}`, file: a.file, methods: ["ACTION"], tables: a.tables,
    authenticated: a.authenticated, machineGated: false, machineGateReadable: a.identityReadable, machineGateGap: a.identityGap,
    usesServiceRole: false, serviceRoleReadable: a.identityReadable,
    ownershipFiltered: a.ownershipFiltered, ownershipReadable: a.ownershipReadable, ownershipGap: a.ownershipGap,
    identityReadable: a.identityReadable, identityGap: a.identityGap,
    dataReadable: a.identityReadable, dataGap: a.identityGap, via: a.importedBy.slice(0, 5),
  }));
}

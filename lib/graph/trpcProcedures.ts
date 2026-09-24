import ts from "typescript";
import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport, stripComments } from "@/lib/deep/clientExposure";
import { resolveViaTsconfigPaths } from "./tsconfigPaths";
import { scriptKindFor } from "./declarations";
import { extractTables, STRONG_USER_AUTH_RE, type RouteFact } from "./routeInventory";
import { calls, middlewareAuthenticates, NOT_HELPERS } from "./serverActionFacts";

/**
 * Facts for tRPC procedures (Step 7G-1), the tRPC counterpart of the server
 * action facts. A procedure is a `router({...})` / `createTRPCRouter({...})`
 * entry whose chain ends in `.query`, `.mutation` or `.subscription`.
 *
 * Identity is read where tRPC resolves it: the `.use(...)` middleware of the
 * base procedure (followed through its declarations, across files) and any
 * `.use(...)` on the procedure itself. A middleware or base that cannot be
 * resolved makes identity UNREADABLE, never anonymous, unless another piece
 * we did read already refuses a caller without a user. Ownership is read in
 * the resolver: a where clause narrowed by what the middleware put in `ctx`.
 */
export type TrpcProcedureFact = {
  file: string; name: string; kind: "query" | "mutation" | "subscription"; base: string;
  identityReadable: boolean; identityGap: string | null; authenticated: boolean;
  tables: string[]; ownershipReadable: boolean; ownershipFiltered: boolean; via: string[];
};

const IGNORED = /(^|\/)(node_modules|\.next|dist|build|vendor)\/|\.(test|spec|e2e)\.[cm]?[jt]sx?$|(^|\/)__tests__\//;
const CODE = /\.[cm]?[jt]sx?$/;
const ROUTER_CALLEE = /^(?:router|createTRPCRouter|createRouter|\w+\.router)$/;
const RESOLVERS = new Set(["query", "mutation", "subscription"]);

// A tRPC middleware that refuses a caller the context has no user for:
// `if (!ctx.session?.user) throw new TRPCError({ code: "UNAUTHORIZED" })`.
// The missing-user test must be the condition of an `if` whose branch throws:
// corpus-d's mutationSessionGuard tests `!ctx.user` only to let such a caller
// through, and throws for a different case.
const CTX_USER_CHECK = /!\s*(?:\w+\.)?ctx\s*\.\s*(?:session|user|userId|auth)\b/;
function ctxGate(text: string): boolean {
  if (!CTX_USER_CHECK.test(text)) return false;
  const sf = ts.createSourceFile("m.ts", text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let gated = false;
  const throws = (node: ts.Node): boolean => ts.isThrowStatement(node) || (!ts.isFunctionLike(node) && ts.forEachChild(node, throws) === true);
  const visit = (node: ts.Node) => {
    if (gated) return;
    if (ts.isIfStatement(node) && CTX_USER_CHECK.test(node.expression.getText(sf)) && throws(node.thenStatement)) gated = true;
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return gated;
}
const refuses = (text: string) => middlewareAuthenticates(text) || ctxGate(text);

// Query-builder calls that carry ctx into a where clause rather than to a
// helper that may narrow on its own (Drizzle operators and chain methods).
const QUERY_BUILDER = new Set(["where", "and", "or", "not", "eq", "ne", "inArray", "notInArray", "isNull", "isNotNull",
  "gt", "gte", "lt", "lte", "like", "ilike", "select", "from", "insert", "update", "delete", "set", "values",
  "returning", "limit", "offset", "orderBy", "findFirst", "findMany", "leftJoin", "innerJoin", "sql", "Number", "toString"]);

type Parsed = { file: RepoFile; sf: ts.SourceFile };

function chainOf(expr: ts.Expression): { root: ts.Expression; links: { name: string; args: readonly ts.Expression[] }[] } {
  const links: { name: string; args: readonly ts.Expression[] }[] = [];
  let node: ts.Expression = expr;
  while (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    links.unshift({ name: node.expression.name.text, args: node.arguments });
    node = node.expression.expression;
  }
  return { root: node, links };
}

export function analyzeTrpcProcedures(files: RepoFile[]): TrpcProcedureFact[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const parsed = new Map<string, Parsed>();
  const parse = (path: string): Parsed | null => {
    const file = byPath.get(path);
    if (!file) return null;
    if (!parsed.has(path)) parsed.set(path, { file, sf: ts.createSourceFile(path, file.content, ts.ScriptTarget.Latest, true, scriptKindFor(path)) });
    return parsed.get(path)!;
  };

  /** The initializer an identifier names in a file: a local declaration, a default export, or an import followed. */
  function declaration(name: string, at: Parsed, depth = 0): { init: ts.Expression; at: Parsed } | null {
    if (depth > 6) return null;
    let found: ts.Expression | null = null;
    let imported: { spec: string; imported: string } | null = null;
    for (const stmt of at.sf.statements) {
      if (ts.isVariableStatement(stmt)) {
        for (const d of stmt.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer) found = d.initializer;
        }
      } else if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier) && stmt.importClause) {
        const clause = stmt.importClause;
        const spec = stmt.moduleSpecifier.text;
        if (clause.name?.text === name) imported = { spec, imported: "default" };
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            if (el.name.text === name) imported = { spec, imported: (el.propertyName ?? el.name).text };
          }
        }
      } else if (ts.isExportDeclaration(stmt) && stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier) &&
          stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
        for (const el of stmt.exportClause.elements) {
          if (el.name.text === name) imported = { spec: stmt.moduleSpecifier.text, imported: (el.propertyName ?? el.name).text };
        }
      }
    }
    if (found) return { init: found, at };
    if (!imported) return null;
    const target = resolveImport(at.file.path, imported.spec, byPath) ?? resolveViaTsconfigPaths(at.file.path, imported.spec, byPath);
    const next = target ? parse(target) : null;
    if (!next) return null;
    if (imported.imported !== "default") return declaration(imported.imported, next, depth + 1);
    for (const stmt of next.sf.statements) {
      if (ts.isExportAssignment(stmt)) {
        return ts.isIdentifier(stmt.expression) ? declaration(stmt.expression.text, next, depth + 1) : { init: stmt.expression, at: next };
      }
    }
    return null;
  }

  type Chain = { texts: string[]; gaps: string[]; via: Set<string> };

  /** The text of one `.use(arg)` middleware, following identifiers and factories. */
  function middleware(arg: ts.Expression, at: Parsed, out: Chain, depth = 0): void {
    if (depth > 6) { out.gaps.push("a middleware chain is too deep to follow"); return; }
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) { out.texts.push(arg.getText(at.sf)); return; }
    if (ts.isCallExpression(arg)) {
      const callee = arg.expression;
      // `middleware(fn)` / `t.middleware(fn)`: the function is the middleware.
      if (/(?:^|\.)middleware$/.test(callee.getText(at.sf))) { out.texts.push(arg.getText(at.sf)); return; }
      // `isAuthed.unstable_pipe(fn)`: the parent runs first.
      if (ts.isPropertyAccessExpression(callee) && /^(?:unstable_pipe|pipe|concat)$/.test(callee.name.text)) {
        out.texts.push(arg.arguments.map((a) => a.getText(at.sf)).join("\n"));
        middleware(callee.expression, at, out, depth + 1);
        return;
      }
      // A factory such as createRateLimitMiddleware(...): read its declaration.
      if (ts.isIdentifier(callee)) { middleware(callee, at, out, depth + 1); return; }
    }
    if (ts.isIdentifier(arg)) {
      const decl = declaration(arg.text, at);
      if (!decl) { out.gaps.push(`the middleware ${arg.text} could not be resolved`); return; }
      out.via.add(decl.at.file.path);
      if (ts.isArrowFunction(decl.init) || ts.isFunctionExpression(decl.init)) { out.texts.push(decl.init.getText(decl.at.sf)); return; }
      middleware(decl.init, decl.at, out, depth + 1);
      return;
    }
    out.gaps.push(`the middleware ${arg.getText(at.sf).slice(0, 40)} could not be read`);
  }

  /** Middleware texts of a procedure chain, following its base back to `t.procedure`. */
  function procedureChain(expr: ts.Expression, at: Parsed, out: Chain, depth = 0): void {
    if (depth > 8) { out.gaps.push("the procedure chain is too deep to follow"); return; }
    const { root, links } = chainOf(expr);
    for (const link of links) {
      if (link.name === "use" && link.args[0]) middleware(link.args[0], at, out);
    }
    // `t.procedure` (or `tRPCContext.procedure`) is the unauthenticated root.
    if (ts.isPropertyAccessExpression(root) && root.name.text === "procedure") return;
    if (!ts.isIdentifier(root)) { out.gaps.push(`the procedure ${root.getText(at.sf).slice(0, 40)} could not be read`); return; }
    const decl = declaration(root.text, at);
    if (!decl) { out.gaps.push(`the procedure ${root.text} could not be resolved`); return; }
    out.via.add(decl.at.file.path);
    procedureChain(decl.init, decl.at, out, depth + 1);
  }

  const facts: TrpcProcedureFact[] = [];
  for (const file of files) {
    if (IGNORED.test(file.path) || !CODE.test(file.path) || !/\.(?:query|mutation|subscription)\s*\(/.test(file.content)) continue;
    const at = parse(file.path)!;
    const seen = new Set<ts.Node>();
    const visitRouter = (literal: ts.ObjectLiteralExpression, prefix: string) => {
      for (const prop of literal.properties) {
        if (!ts.isPropertyAssignment(prop)) continue;
        const key = prop.name.getText(at.sf).replace(/^["']|["']$/g, "");
        const init = prop.initializer;
        if (ts.isCallExpression(init) && ROUTER_CALLEE.test(init.expression.getText(at.sf)) &&
            init.arguments[0] && ts.isObjectLiteralExpression(init.arguments[0])) {
          seen.add(init);
          visitRouter(init.arguments[0], `${prefix}${key}.`);
          continue;
        }
        const { links } = chainOf(init);
        const last = links[links.length - 1];
        if (!ts.isCallExpression(init) || !last || !RESOLVERS.has(last.name)) continue;
        const chain: Chain = { texts: [], gaps: [], via: new Set() };
        procedureChain(init, at, chain);
        const body = stripComments(last.args[0]?.getText(at.sf) ?? "");
        facts.push(fact(file.path, `${prefix}${key}`, last.name as TrpcProcedureFact["kind"],
          chainOf(init).root.getText(at.sf), chain, body));
      }
    };
    const walk = (node: ts.Node) => {
      if (ts.isCallExpression(node) && !seen.has(node) && ROUTER_CALLEE.test(node.expression.getText(at.sf)) &&
          node.arguments[0] && ts.isObjectLiteralExpression(node.arguments[0])) {
        seen.add(node);
        visitRouter(node.arguments[0], "");
      }
      ts.forEachChild(node, walk);
    };
    walk(at.sf);
  }
  return facts.sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
}

function balanced(text: string, open: number): string {
  const close = text[open] === "(" ? ")" : "}";
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === text[open]) depth++;
    else if (text[i] === close && --depth === 0) return text.slice(open, i + 1);
  }
  return text.slice(open);
}

function fact(file: string, name: string, kind: TrpcProcedureFact["kind"], base: string,
  chain: { texts: string[]; gaps: string[]; via: Set<string> }, body: string): TrpcProcedureFact {
  const identity = chain.texts.join("\n");
  const authenticated = refuses(identity) || STRONG_USER_AUTH_RE.test(body) || refuses(body);
  const identityReadable = authenticated || chain.gaps.length === 0;
  const identityGap = identityReadable ? null : chain.gaps[0];
  const tables = extractTables(body);
  // Identity values a where clause may narrow by: ctx itself, keys the
  // middleware injects into ctx, and names destructured from ctx.
  const ctxKeys = [...identity.matchAll(/ctx\s*:\s*\{([^}]*)\}/g)].flatMap((m) => m[1].split(",").map((k) => k.split(":")[0].trim()));
  const destructured = [...body.matchAll(/const\s*\{([^}]*)\}\s*=\s*(?:\w+\.)?ctx\b/g)].flatMap((m) => m[1].split(",").map((k) => k.trim().split(/\s*:\s*/).pop()!));
  const aliases = [...body.matchAll(/(?:const|let)\s+(\w+)\s*=\s*(?:\w+\.)?ctx\.\w+/g)].map((m) => m[1]);
  const names = [...new Set([...ctxKeys, ...destructured, ...aliases])].filter((k) => /^\w+$/.test(k) && k !== "ctx");
  const identityRef = new RegExp(`\\bctx\\.\\w+${names.map((k) => `|\\b${k}\\b`).join("")}`);
  const wheres = [...body.matchAll(/\bwhere\s*:\s*\{|\.where\s*\(/g)].map((m) => balanced(body, (m.index ?? 0) + m[0].length - 1));
  const ownershipFiltered = tables.length > 0 && wheres.some((w) => identityRef.test(w));
  // "Not filtered" is claimed only when the resolver's own where clauses were
  // read and identity is not handed to a helper that may narrow on its own.
  const handedToHelper = calls(body).some((c) => !NOT_HELPERS.has(c.callee) && !QUERY_BUILDER.has(c.callee) && identityRef.test(c.args));
  const ownershipReadable = identityReadable && (ownershipFiltered || (tables.length > 0 && wheres.length > 0 && !handedToHelper));
  return { file, name, kind, base, identityReadable, identityGap, authenticated, tables, ownershipReadable, ownershipFiltered,
    via: [...chain.via].filter((p) => p !== file).sort() };
}

/**
 * tRPC procedures as route facts (7G), so the audit ranks, prompts and guards
 * them exactly like route handlers. The path `trpc:<file>#<name>` is what a
 * hypothesis cites. Like server actions, service-role, machine-gate and data
 * readability carry the identity readability.
 */
export function trpcRoutes(files: RepoFile[]): RouteFact[] {
  return analyzeTrpcProcedures(files).map((p) => ({
    path: `trpc:${p.file}#${p.name}`, file: p.file, methods: [p.kind.toUpperCase()], tables: p.tables,
    authenticated: p.authenticated, machineGated: false, machineGateReadable: p.identityReadable, machineGateGap: p.identityGap,
    usesServiceRole: false, serviceRoleReadable: p.identityReadable,
    ownershipFiltered: p.ownershipFiltered, ownershipReadable: p.ownershipReadable, ownershipGap: p.identityGap,
    identityReadable: p.identityReadable, identityGap: p.identityGap,
    dataReadable: p.identityReadable, dataGap: p.identityGap, via: p.via.slice(0, 5),
  }));
}

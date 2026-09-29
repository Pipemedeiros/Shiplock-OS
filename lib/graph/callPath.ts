import ts from "typescript";
import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport, stripComments } from "@/lib/deep/clientExposure";
import { blankSpans, declarationSpans, scriptKindFor } from "./declarations";

/**
 * PER-CALL-PATH ATTRIBUTION: a route is judged on the code its handler runs,
 * not on every function in every file it imports.
 *
 * `reachableSources()` in routeInventory.ts follows imports two hops and hands
 * the collectors whole files. That is how corpus-b's
 * /api/conversations/[[...conversations]] came to carry `ownershipFiltered:
 * true`: the shared conversation service it imports contains a genuine
 * `participants: { some: { userId } }` filter -- in `getUnreadMessages`, a
 * function the handler never calls. The evidence was real, in a path the
 * request never takes. No pattern tightening reaches that, because the pattern
 * is right about the line and wrong about whether the line runs.
 *
 * This module follows the actual call graph from the route's exported handler
 * with the TypeScript parser: the handler's body, every local function it
 * calls, the method it selects on an object literal it calls through, the
 * wrapper it is passed to (so what a wrapper does is read from its body, not
 * guessed from its name), and the module it re-exports. It then renders each
 * reached file as text in which everything NOT on that path is blanked, and
 * hands that text to the same collectors as before. The patterns are
 * unchanged; only what they are allowed to see has changed.
 *
 * Two further rules fall out of having the call sites:
 *
 *   UNSUPPLIED PARAMETERS. `messageService.addMessage({ conversationId,
 *   content, viewId, viewerId })` never passes `userId`, and inside addMessage
 *   `userId` is therefore undefined. A filter by a value nobody supplied is not
 *   a filter on this path, so within a callee every parameter that NO call
 *   site on the path supplies is renamed before the collectors see it.
 *
 *   HANDLER HOSTS. `export { default } from "@/ee/.../route"` puts the whole
 *   handler one file away. The file the handler lives in is the route, not a
 *   helper: its queries are the route's queries and its shared-secret check
 *   is the route's gate. A file reached only by being CALLED remains a helper
 *   and keeps the existing conservatism.
 *
 * Fails closed toward the old behaviour: if no handler export can be found,
 * or the walk exceeds its budget, `null` is returned and the caller falls back
 * to whole-file attribution. Under-reading invents attack paths; over-reading
 * only misses them, and this file's header commits to the second.
 */

export interface TracedSource {
  path: string;
  /** Comment-stripped text with declarations and unexecuted bodies blanked. */
  src: string;
  /**
   * True when this file was reached ONLY as configuration handed to an
   * identity call -- `getServerSession(authOptions)`. Its callbacks run inside
   * identity resolution; its tables and filters are not the route's.
   */
  identityInfrastructure: boolean;
  /**
   * The comment-stripped original. Needed by exactly one consumer: the names a
   * request destructure bound are read from here, because in `src` the
   * destructure is a declaration and is already blank.
   */
  original: string;
  /** True when this file holds the handler itself rather than a helper it calls. */
  host: boolean;
}

export interface Trace {
  sources: TracedSource[];
  /** HTTP methods read from the entry's exports, including `export { h as GET }`. */
  methods: string[];
  /**
   * Names the handler destructures from the object its wrapper hands it:
   * `withPartnerProfile(async ({ partner }) => …)` injects `partner`. The
   * wrapper established those values; whether that makes them the caller's
   * identity depends on whether the wrapper resolved one, which the caller of
   * this module decides from `wrapperPaths`.
   */
  injected: string[];
  /** Files holding the wrappers the handler was passed to. */
  wrapperPaths: string[];
  /**
   * Files in which an identity call runs only under a condition on the
   * enclosing function's own parameter -- `switch (authenticationMethod)`.
   * Such a call is renamed in the rendered text so it is not read as a gate,
   * and listed here so the route is disclosed as unreadable, not anonymous.
   */
  conditionalIdentityPaths: string[];
  /**
   * Files the executed path reached for but the hop budget did not enter
   * (Q24). What runs there was not read; a caller may disclose it.
   */
  unfollowed: string[];
}

export interface TraceOptions {
  /** Whether a callee, by its source text, resolves the caller's identity. */
  isIdentityCall?: (calleeText: string) => boolean;
  /**
   * Named exports to start from instead of the HTTP handlers: a server action
   * is one exported function (Q24). Module-level statements are then not
   * walked, because they run at import, not per call.
   */
  roots?: string[];
}

/** Names Next.js itself injects; never identity, whatever wraps the handler. */
const FRAMEWORK_INJECTED = new Set(["req", "request", "res", "response", "params", "searchParams", "headers", "body", "query", "ctx", "context", "next"]);

const METHOD_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/** File hops from the entry, matching MAX_IMPORT_DEPTH in routeInventory.ts. */
const MAX_FILE_HOPS = 2;
/** Walk budgets. Exceeding one means fall back, never truncate. */
const MAX_FILES = 80;
const MAX_INCLUDED = 4_000;

/** What a callee's parameter names look like at one call site. */
type Supplied = Set<string> | "unknown";

type Value = { mod: Module; node: ts.Node };

interface ImportRef {
  spec: string;
  /** "default", "*", or the exported name. */
  imported: string;
}

type ExportRef = { kind: "local"; name: string } | { kind: "node"; node: ts.Node } | { kind: "reexport"; spec: string; imported: string };

interface Module {
  path: string;
  sf: ts.SourceFile;
  locals: Map<string, ts.Node>;
  imports: Map<string, ImportRef>;
  exports: Map<string, ExportRef>;
  starExports: string[];
  /** Function-like nodes anywhere in the file, for blanking the unexecuted ones. */
  functions: ts.Node[];
}

const parseCache = new Map<string, Module>();
const PARSE_CACHE_LIMIT = 2_000;

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === kind) ?? false;
}

function bindingNames(name: ts.BindingName, out: string[] = []): string[] {
  if (ts.isIdentifier(name)) out.push(name.text);
  else for (const el of name.elements) if (ts.isBindingElement(el)) bindingNames(el.name, out);
  return out;
}

function analyzeModule(file: RepoFile): Module {
  const key = `${file.path} ${file.content}`;
  const hit = parseCache.get(key);
  if (hit) return hit;

  const sf = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, scriptKindFor(file.path));
  const mod: Module = { path: file.path, sf, locals: new Map(), imports: new Map(), exports: new Map(), starExports: [], functions: [] };

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt)) {
      if (stmt.importClause?.isTypeOnly || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const spec = stmt.moduleSpecifier.text;
      const clause = stmt.importClause;
      if (!clause) continue;
      if (clause.name) mod.imports.set(clause.name.text, { spec, imported: "default" });
      const nb = clause.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) mod.imports.set(nb.name.text, { spec, imported: "*" });
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) {
          if (el.isTypeOnly) continue;
          mod.imports.set(el.name.text, { spec, imported: (el.propertyName ?? el.name).text });
        }
      }
      continue;
    }
    if (ts.isExportDeclaration(stmt)) {
      if (stmt.isTypeOnly) continue;
      const spec = stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier) ? stmt.moduleSpecifier.text : null;
      if (!stmt.exportClause) {
        if (spec) mod.starExports.push(spec);
        continue;
      }
      if (ts.isNamedExports(stmt.exportClause)) {
        for (const el of stmt.exportClause.elements) {
          const exported = el.name.text;
          const local = (el.propertyName ?? el.name).text;
          mod.exports.set(exported, spec ? { kind: "reexport", spec, imported: local } : { kind: "local", name: local });
        }
      }
      continue;
    }
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      mod.exports.set("default", { kind: "node", node: stmt.expression });
      continue;
    }
    if (ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt)) {
      const exported = hasModifier(stmt, ts.SyntaxKind.ExportKeyword);
      if (stmt.name) {
        mod.locals.set(stmt.name.text, stmt);
        if (exported) mod.exports.set(stmt.name.text, { kind: "local", name: stmt.name.text });
      }
      if (exported && hasModifier(stmt, ts.SyntaxKind.DefaultKeyword)) mod.exports.set("default", { kind: "node", node: stmt });
      continue;
    }
    if (ts.isVariableStatement(stmt)) {
      const exported = hasModifier(stmt, ts.SyntaxKind.ExportKeyword);
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) {
          mod.locals.set(decl.name.text, decl);
          if (exported) mod.exports.set(decl.name.text, { kind: "local", name: decl.name.text });
        } else if (decl.initializer) {
          // `export const { GET, POST } = toNextJsHandler(auth)`: every name is
          // whatever the initializer produces.
          for (const name of bindingNames(decl.name)) {
            mod.locals.set(name, decl.initializer);
            if (exported) mod.exports.set(name, { kind: "local", name });
          }
        }
      }
    }
  }

  const collect = (node: ts.Node): void => {
    if (isFunctionLike(node)) mod.functions.push(node);
    ts.forEachChild(node, collect);
  };
  collect(sf);

  if (parseCache.size >= PARSE_CACHE_LIMIT) parseCache.clear();
  parseCache.set(key, mod);
  return mod;
}

class Walker {
  private readonly modules = new Map<string, Module>();
  private readonly hops = new Map<string, number>();
  /** Executed function-like nodes and included object properties, per file. */
  readonly executed = new Map<string, Set<ts.Node>>();
  readonly hosts = new Set<string>();
  /** Files reached as ordinary code, and files reached as identity-call configuration. */
  readonly reachedNormally = new Set<string>();
  readonly reachedAsIdentityConfig = new Set<string>();
  readonly injected = new Set<string>();
  readonly wrapperPaths = new Set<string>();
  /** Identity calls that run only under a condition on a parameter, per file. */
  readonly conditionalIdentityCalls = new Map<string, Set<ts.Node>>();
  /** Files an executed reference resolved into but the hop budget did not enter (Q24). */
  readonly beyondBudget = new Set<string>();
  /** Every way a callee was reached, so unsupplied names can be intersected. */
  private readonly reached = new Map<ts.Node, Supplied[]>();
  private readonly visited = new Set<string>();
  private included = 0;
  overBudget = false;

  constructor(
    private readonly byPath: Map<string, RepoFile>,
    private readonly isIdentityCall: (calleeText: string) => boolean,
  ) {}

  module(path: string): Module | null {
    const hit = this.modules.get(path);
    if (hit) return hit;
    const file = this.byPath.get(path);
    if (!file) return null;
    const mod = analyzeModule(file);
    this.modules.set(path, mod);
    return mod;
  }

  private enter(from: Module, spec: string): Module | null {
    const path = resolveImport(from.path, spec, this.byPath);
    if (!path) return null;
    const hop = (this.hops.get(from.path) ?? 0) + 1;
    const known = this.hops.get(path);
    if (known !== undefined && known <= hop) return this.module(path);
    if (hop > MAX_FILE_HOPS) {
      this.beyondBudget.add(path);
      return null;
    }
    if (this.modules.size >= MAX_FILES && !this.modules.has(path)) {
      this.overBudget = true;
      return null;
    }
    this.hops.set(path, hop);
    return this.module(path);
  }

  /** A name in module scope: a local declaration or an import, resolved. */
  resolveName(mod: Module, name: string, depth = 0): Value | null {
    if (depth > 8) return null;
    const local = mod.locals.get(name);
    if (local) return { mod, node: local };
    const imp = mod.imports.get(name);
    if (!imp) return null;
    const target = this.enter(mod, imp.spec);
    if (!target) return null;
    if (imp.imported === "*") return { mod: target, node: target.sf };
    return this.resolveExport(target, imp.imported, depth + 1);
  }

  resolveExport(mod: Module, exported: string, depth = 0): Value | null {
    if (depth > 8) return null;
    const ref = mod.exports.get(exported);
    if (ref) {
      if (ref.kind === "node") return { mod, node: ref.node };
      if (ref.kind === "local") return this.resolveName(mod, ref.name, depth + 1);
      const target = this.enter(mod, ref.spec);
      return target ? this.resolveExport(target, ref.imported, depth + 1) : null;
    }
    for (const spec of mod.starExports) {
      const target = this.enter(mod, spec);
      const found = target ? this.resolveExport(target, exported, depth + 1) : null;
      if (found) return found;
    }
    return null;
  }

  /** `a.b.c` where `a` is a module-scope name: the value at the end of the path, if readable. */
  resolveChain(mod: Module, expr: ts.Expression): Value | null {
    const parts: string[] = [];
    let cur: ts.Expression = expr;
    while (true) {
      if (ts.isPropertyAccessExpression(cur)) {
        parts.unshift(cur.name.text);
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur)) {
        if (!ts.isStringLiteral(cur.argumentExpression)) return null; // dynamic key: caller includes the whole object
        parts.unshift(cur.argumentExpression.text);
        cur = cur.expression;
      } else if (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur)) {
        cur = cur.expression;
      } else {
        break;
      }
    }
    if (!ts.isIdentifier(cur)) return null;
    let value = this.resolveName(mod, cur.text);
    for (const part of parts) {
      if (!value) return null;
      value = this.member(value, part);
    }
    return value;
  }

  private member(value: Value, name: string): Value | null {
    const node = this.unwrap(value.node);
    if (ts.isSourceFile(node)) return this.resolveExport(value.mod, name);
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        const key = prop.name && (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name)) ? prop.name.text : null;
        if (key !== name) continue;
        if (ts.isPropertyAssignment(prop)) return { mod: value.mod, node: prop.initializer };
        if (ts.isShorthandPropertyAssignment(prop)) return this.resolveName(value.mod, prop.name.text);
        if (ts.isMethodDeclaration(prop)) return { mod: value.mod, node: prop };
      }
      return null;
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      for (const m of node.members) {
        if (m.name && (ts.isIdentifier(m.name) || ts.isStringLiteral(m.name)) && m.name.text === name) return { mod: value.mod, node: m };
      }
    }
    return null;
  }

  /** A variable declaration stands for its initializer. */
  private unwrap(node: ts.Node): ts.Node {
    if (ts.isVariableDeclaration(node) && node.initializer) return this.unwrap(node.initializer);
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node)) {
      return this.unwrap(node.expression);
    }
    return node;
  }

  private mark(mod: Module, node: ts.Node, infra = false): boolean {
    (infra ? this.reachedAsIdentityConfig : this.reachedNormally).add(mod.path);
    const key = `${mod.path} ${node.pos} ${node.kind}`;
    if (this.visited.has(key)) return false;
    this.visited.add(key);
    if (++this.included > MAX_INCLUDED) this.overBudget = true;
    let set = this.executed.get(mod.path);
    if (!set) this.executed.set(mod.path, (set = new Set()));
    set.add(node);
    return true;
  }

  /**
   * Include a VALUE the route reaches. `root` is true while we are still
   * finding the handler itself (the export, what it re-exports, the function
   * passed to a wrapper): a function reached that way makes its file a host.
   * A wrapper's own body, and anything reached by being called, is a helper.
   */
  include(value: Value, root: boolean, supplied: Supplied = "unknown", infra = false): void {
    if (this.overBudget) return;
    const { mod } = value;
    const node = this.unwrap(value.node);

    if (isFunctionLike(node)) {
      const list = this.reached.get(node) ?? [];
      list.push(supplied);
      this.reached.set(node, list);
      if (!this.mark(mod, node, infra)) return;
      if (root) this.hosts.add(mod.path);
      if (node.body) this.walk(mod, node.body, this.shadow(node, new Set()), infra, node);
      return;
    }
    if (!this.mark(mod, node, infra)) return;

    if (ts.isIdentifier(node)) {
      const target = this.resolveName(mod, node.text);
      if (!target) return;
      // Root follows a name to a function or an object of functions -- the
      // handler by another name. It does not follow a name to a VALUE that was
      // computed by a call: `schemas: ZCreateBody` resolves to a Zod chain
      // whose refine() callbacks are not the route, and treating the schema
      // file as a host credited its contents to the route.
      const resolved = this.unwrap(target.node);
      const computed = ts.isCallExpression(resolved) || ts.isNewExpression(resolved);
      this.include(target, root && !computed, "unknown", infra);
      return;
    }
    if (ts.isSourceFile(node)) return; // a namespace import as a whole: nothing to execute yet
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (ts.isPropertyAssignment(prop)) this.include({ mod, node: prop.initializer }, root, "unknown", infra);
        else if (ts.isShorthandPropertyAssignment(prop)) this.include({ mod, node: prop.name }, root, "unknown", infra);
        else if (ts.isMethodDeclaration(prop)) this.include({ mod, node: prop }, root, "unknown", infra);
        else if (ts.isSpreadAssignment(prop)) this.include({ mod, node: prop.expression }, root, "unknown", infra);
      }
      return;
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      for (const m of node.members) {
        if (isFunctionLike(m)) this.include({ mod, node: m }, root, "unknown", infra);
        else if (ts.isPropertyDeclaration(m) && m.initializer) this.include({ mod, node: m.initializer }, false, "unknown", infra);
      }
      return;
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      // A wrapper: `withWorkspace(handler)`. The handler keeps root; the
      // wrapper's body is read (so a local wrapper's gate is seen) as a helper.
      const callee = this.resolveChain(mod, node.expression);
      const identity = this.isIdentityCall(node.expression.getText(mod.sf));
      if (callee) {
        this.include(callee, false, this.suppliedAt(node, this.unwrap(callee.node)), infra);
        if (root) this.recordWrapper(callee, node);
      } else {
        this.walk(mod, node.expression, new Set(), infra);
      }
      // Configuration handed to an identity call is identity infrastructure.
      for (const arg of node.arguments ?? []) this.include({ mod, node: arg }, root, "unknown", infra || identity);
      return;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const target = this.resolveChain(mod, node);
      if (target) this.include(target, root, "unknown", infra);
      else this.walk(mod, node, new Set(), infra);
      return;
    }
    // Any other expression: walk it for references.
    this.walk(mod, node, new Set(), infra);
  }

  /** `withX(async ({ partner }) => …)` at the root: remember the wrapper and what its handler destructures. */
  private recordWrapper(callee: Value, call: ts.CallExpression | ts.NewExpression): void {
    this.wrapperPaths.add(callee.mod.path);
    for (const arg of call.arguments ?? []) {
      const fn = this.unwrap(arg);
      if (!isFunctionLike(fn)) continue;
      const first = fn.parameters[0];
      if (!first || !ts.isObjectBindingPattern(first.name)) continue;
      for (const el of first.name.elements) {
        if (ts.isIdentifier(el.name) && !FRAMEWORK_INJECTED.has(el.name.text)) this.injected.add(el.name.text);
      }
    }
  }

  /**
   * An identity call that runs only under a condition on the enclosing
   * function's OWN parameter: `switch (authenticationMethod) { case Session:
   * return getSession() }`. That is a wrapper that resolves a session when an
   * option says so, and reading it as a gate for every route it wraps asserts
   * a gate we did not read. A condition on a request-derived local (`if
   * (apiKey) … else getSession()`) is not this: both branches still identify.
   */
  private isOptionConditional(call: ts.Node, fn: ts.FunctionLikeDeclaration): boolean {
    const params = new Set<string>();
    for (const p of fn.parameters) for (const n of bindingNames(p.name)) params.add(n);
    for (const n of FRAMEWORK_INJECTED) params.delete(n);
    if (params.size === 0) return false;
    const mentionsParam = (expr: ts.Node): boolean => {
      let found = false;
      const visit = (n: ts.Node): void => {
        if (found) return;
        if (ts.isIdentifier(n) && params.has(n.text)) found = true;
        else ts.forEachChild(n, visit);
      };
      visit(expr);
      return found;
    };
    for (let p: ts.Node | undefined = call.parent; p && p !== fn; p = p.parent) {
      if (ts.isIfStatement(p) && mentionsParam(p.expression)) return true;
      if (ts.isConditionalExpression(p) && mentionsParam(p.condition)) return true;
      if (ts.isSwitchStatement(p) && mentionsParam(p.expression)) return true;
      if (
        ts.isBinaryExpression(p) &&
        (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
          p.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) &&
        mentionsParam(p.left)
      ) {
        return true;
      }
    }
    return false;
  }

  /** Names a function declares, which shadow module scope inside it. */
  private shadow(fn: ts.FunctionLikeDeclaration, outer: Set<string>): Set<string> {
    const names = new Set(outer);
    for (const p of fn.parameters) for (const n of bindingNames(p.name)) names.add(n);
    const scan = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node)) for (const n of bindingNames(node.name)) names.add(n);
      else if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) names.add(node.name.text);
      ts.forEachChild(node, scan);
    };
    if (fn.body) scan(fn.body);
    return names;
  }

  /** Which of `callee`'s parameter names this call site leaves unsupplied. */
  private suppliedAt(call: ts.CallExpression | ts.NewExpression, callee: ts.Node): Supplied {
    if (!isFunctionLike(callee)) return "unknown";
    const args = call.arguments ?? [];
    const unsupplied = new Set<string>();
    callee.parameters.forEach((p, i) => {
      if (p.dotDotDotToken) return;
      const arg = args[i];
      if (arg === undefined) {
        if (!p.initializer) for (const n of bindingNames(p.name)) unsupplied.add(n);
        return;
      }
      if (ts.isObjectBindingPattern(p.name) && ts.isObjectLiteralExpression(arg) && !arg.properties.some(ts.isSpreadAssignment)) {
        const keys = new Set<string>();
        for (const prop of arg.properties) {
          if (prop.name && (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name))) keys.add(prop.name.text);
          else return; // a computed key: cannot tell what is supplied
        }
        for (const el of p.name.elements) {
          if (el.dotDotDotToken || el.initializer || !ts.isIdentifier(el.name)) continue;
          const key = el.propertyName && (ts.isIdentifier(el.propertyName) || ts.isStringLiteral(el.propertyName)) ? el.propertyName.text : el.name.text;
          if (!keys.has(key)) unsupplied.add(el.name.text);
        }
      }
    });
    // The set is what is NOT supplied; an empty set means everything was.
    return unsupplied;
  }

  /** Walk executed code for references and calls. */
  private walk(mod: Module, node: ts.Node, shadow: Set<string>, infra = false, fn?: ts.FunctionLikeDeclaration): void {
    if (this.overBudget) return;
    const visit = (n: ts.Node): void => {
      if (this.overBudget) return;
      if (ts.isTypeNode(n) || ts.isImportDeclaration(n) || ts.isInterfaceDeclaration(n) || ts.isTypeAliasDeclaration(n)) return;

      if (isFunctionLike(n)) {
        // Nested in executed code: executed by containment, with its own scope.
        const list = this.reached.get(n) ?? [];
        list.push("unknown");
        this.reached.set(n, list);
        this.mark(mod, n, infra);
        if (n.body) this.walk(mod, n.body, this.shadow(n, shadow), infra, n);
        return;
      }

      if (ts.isCallExpression(n) || ts.isNewExpression(n)) {
        const identity = this.isIdentityCall(n.expression.getText(mod.sf));
        if (identity && fn && !this.hosts.has(mod.path) && this.isOptionConditional(n, fn)) {
          let set = this.conditionalIdentityCalls.get(mod.path);
          if (!set) this.conditionalIdentityCalls.set(mod.path, (set = new Set()));
          set.add(n.expression);
        }
        const base = this.baseIdentifier(n.expression);
        if (base && !shadow.has(base.text)) {
          const callee = this.resolveChain(mod, n.expression);
          if (callee) {
            this.include(callee, false, this.suppliedAt(n, this.unwrap(callee.node)), infra);
          } else {
            const whole = this.resolveName(mod, base.text);
            if (whole) this.include(whole, false, "unknown", infra); // dynamic member: whatever it selects may run
          }
        } else {
          visit(n.expression);
        }
        // Configuration handed to an identity call is identity infrastructure:
        // whatever it reaches was reached inside identity resolution.
        for (const arg of n.arguments ?? []) {
          const target = identity && ts.isIdentifier(arg) && !shadow.has(arg.text) ? this.resolveName(mod, arg.text) : null;
          if (target) this.include(target, false, "unknown", true);
          else visit(arg);
        }
        return;
      }

      if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
        const base = this.baseIdentifier(n);
        if (base && !shadow.has(base.text)) {
          const target = this.resolveChain(mod, n);
          if (target) this.include(target, false, "unknown", infra);
          else {
            const whole = this.resolveName(mod, base.text);
            if (whole) this.include(whole, false, "unknown", infra);
          }
        }
        // The key of an element access can be an expression in its own right.
        if (ts.isElementAccessExpression(n)) visit(n.argumentExpression);
        else if (!base) visit(n.expression);
        return;
      }

      if (ts.isIdentifier(n) && this.isValueReference(n) && !shadow.has(n.text)) {
        const target = this.resolveName(mod, n.text);
        if (target) this.include(target, false, "unknown", infra);
        return;
      }

      ts.forEachChild(n, visit);
    };
    visit(node);
  }

  private baseIdentifier(expr: ts.Expression): ts.Identifier | null {
    let cur: ts.Expression = expr;
    while (true) {
      if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) cur = cur.expression;
      else if (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur)) cur = cur.expression;
      else break;
    }
    return ts.isIdentifier(cur) ? cur : null;
  }

  /** An identifier that reads a value, as opposed to naming a property or a declaration. */
  private isValueReference(id: ts.Identifier): boolean {
    const p = id.parent;
    if (!p) return false;
    if (ts.isPropertyAccessExpression(p) && p.name === id) return false;
    if (ts.isPropertyAssignment(p) && p.name === id) return false;
    if (ts.isBindingElement(p) && p.propertyName === id) return false;
    if (ts.isVariableDeclaration(p) && p.name === id) return false;
    if (ts.isParameter(p) && p.name === id) return false;
    if ((ts.isFunctionDeclaration(p) || ts.isClassDeclaration(p) || ts.isMethodDeclaration(p)) && p.name === id) return false;
    if (ts.isLabeledStatement(p) || ts.isBreakOrContinueStatement(p)) return false;
    return true;
  }

  /** Parameter names that no reaching call site supplied, per executed callee. */
  neutralised(fn: ts.Node): Set<string> {
    const events = this.reached.get(fn);
    if (!events || events.length === 0) return new Set<string>();
    const sets: Set<string>[] = [];
    for (const ev of events) {
      if (ev === "unknown") return new Set<string>();
      sets.push(ev);
    }
    const result = new Set<string>();
    for (const name of sets[0]) if (sets.every((s) => s.has(name))) result.add(name);
    return result;
  }
}

/**
 * The route's handler exports: `{ name, node }` for GET/POST/…, "default",
 * and re-exports of either. Empty when the file exports nothing we recognise.
 */
function handlerRoots(mod: Module): { name: string; ref: ExportRef }[] {
  const out: { name: string; ref: ExportRef }[] = [];
  for (const [name, ref] of mod.exports) {
    if (METHOD_NAMES.has(name) || name === "default") out.push({ name, ref });
  }
  return out;
}

/** Text of `mod` with everything off the path blanked and unsupplied names renamed. */
function render(walker: Walker, mod: Module): string {
  const src = mod.sf.text;
  const executed = walker.executed.get(mod.path) ?? new Set<ts.Node>();
  const spans = declarationSpans(mod.sf);

  const insideExecuted = (node: ts.Node): boolean => {
    for (let p: ts.Node | undefined = node; p; p = p.parent) if (executed.has(p)) return true;
    return false;
  };
  for (const fn of mod.functions) {
    if (executed.has(fn) || insideExecuted(fn)) continue;
    // A declaration or method that never runs is blanked WHOLE, name included.
    // Blanking only the body left `export async function verifyLinkSession(`
    // in the text, and the strong-auth pattern read that header as a session
    // check on a route that only ever calls createLinkSession(). A header is
    // shape. An arrow or function expression keeps its (blank) parameter list
    // so the assignment around it still parses as text.
    if (ts.isFunctionDeclaration(fn) || ts.isMethodDeclaration(fn) || ts.isAccessor(fn) || ts.isConstructorDeclaration(fn)) {
      spans.push([fn.getStart(mod.sf), fn.end]);
      continue;
    }
    const body = (fn as ts.FunctionLikeDeclaration).body;
    if (body) spans.push([body.getStart(mod.sf), body.end]);
  }
  let text = blankSpans(src, spans);

  // Rename, from the end so earlier offsets stay valid.
  const renames: [number, number, string?][] = [];
  for (const fn of executed) {
    if (!isFunctionLike(fn) || !fn.body) continue;
    const names = walker.neutralised(fn);
    if (names.size === 0) continue;
    const visit = (n: ts.Node): void => {
      if (isFunctionLike(n) && n !== fn) {
        // A nested function may redeclare the name; keep it simple and stop.
        for (const p of n.parameters) for (const b of bindingNames(p.name)) if (names.has(b)) return;
      }
      if (ts.isIdentifier(n) && names.has(n.text) && isRenamable(n)) renames.push([n.getStart(mod.sf), n.end]);
      ts.forEachChild(n, visit);
    };
    visit(fn.body);
  }
  // Option-conditional identity calls: the callee is renamed so no pattern
  // reads it as a gate; the file is listed on the trace so the route is
  // disclosed as unreadable instead.
  for (const callee of walker.conditionalIdentityCalls.get(mod.path) ?? []) {
    renames.push([callee.getStart(mod.sf), callee.end, "optionConditionalIdentityCall"]);
  }
  renames.sort((a, b) => b[0] - a[0]);
  for (const [start, end, to] of renames) {
    if (text.slice(start, end).trim().length === 0) continue; // already blanked
    text = text.slice(0, start) + (to ?? "unsuppliedArg") + text.slice(end);
  }
  return stripComments(text);
}

function isRenamable(id: ts.Identifier): boolean {
  const p = id.parent;
  if (!p) return false;
  if (ts.isPropertyAccessExpression(p) && p.name === id) return false; // x.userId is a column
  if (ts.isPropertyAssignment(p) && p.name === id) return false; // { userId: x } key
  if (ts.isBindingElement(p) && p.propertyName === id) return false;
  return true;
}

/**
 * Executed sources for a route, or null when the handler could not be found
 * or the walk ran out of budget (the caller then reads whole files as before).
 */
export function traceExecutedSources(entry: RepoFile, byPath: Map<string, RepoFile>, options: TraceOptions = {}): Trace | null {
  const walker = new Walker(byPath, options.isIdentityCall ?? (() => false));
  const mod = walker.module(entry.path);
  if (!mod) return null;

  const roots = options.roots
    ? options.roots.flatMap((name) => { const ref = mod.exports.get(name); return ref ? [{ name, ref }] : []; })
    : handlerRoots(mod);
  if (roots.length === 0) return null;

  walker.hosts.add(entry.path);
  const methods = new Set<string>();
  for (const { name, ref } of roots) {
    if (METHOD_NAMES.has(name)) methods.add(name);
    const value =
      ref.kind === "node" ? { mod, node: ref.node } : ref.kind === "local" ? walker.resolveName(mod, ref.name) : walker.resolveExport(mod, name);
    if (value) walker.include(value, true);
  }
  if (methods.size === 0 && roots.some((r) => r.name === "default")) methods.add("ALL");

  // Module-level code in the entry runs on every request: `const app = new
  // Hono()` and the `app.get("/x", handler)` registrations below it. Callbacks
  // registered that way are the route, so the top-level statements are walked
  // as if executed under the handler root.
  if (!options.roots) {
    for (const stmt of mod.sf.statements) {
      if (ts.isExpressionStatement(stmt)) walker.include({ mod, node: stmt.expression }, true);
    }
  }

  if (walker.overBudget) return null;

  const sources: TracedSource[] = [];
  const order = [entry.path, ...[...walker.executed.keys()].filter((p) => p !== entry.path).sort()];
  for (const path of order) {
    const m = walker.module(path);
    if (!m) continue;
    if (path !== entry.path && !(walker.executed.get(path)?.size)) continue;
    sources.push({
      path,
      src: render(walker, m),
      original: stripComments(m.sf.text),
      host: walker.hosts.has(path),
      identityInfrastructure: walker.reachedAsIdentityConfig.has(path) && !walker.reachedNormally.has(path),
    });
  }
  return {
    sources,
    methods: [...methods].sort(),
    injected: [...walker.injected].sort(),
    wrapperPaths: [...walker.wrapperPaths].sort(),
    conditionalIdentityPaths: [...walker.conditionalIdentityCalls.keys()].sort(),
    unfollowed: [...walker.beyondBudget].filter((p) => !walker.executed.has(p)).sort(),
  };
}

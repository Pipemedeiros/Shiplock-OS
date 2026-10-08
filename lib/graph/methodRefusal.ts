import ts from "typescript";
import { stripComments } from "@/lib/deep/clientExposure";
import { STRONG_USER_AUTH_RE } from "./routeInventory";

/**
 * Which exported handlers in a route file we READ as never refusing an
 * anonymous caller (R1b, 2026-10-08).
 *
 * `RouteFact.authenticated` is route-wide and means "some handler here resolves
 * the caller". It is not "every handler refuses anonymous callers": in three of
 * four planted sign-in holes one method kept its 401 while the planted method
 * lost it, the route still read as signed in, and the agent was told so.
 *
 * Conservative in the direction that keeps a method OFF this list: a handler is
 * listed only when it is a function written in the route file and nothing in
 * it may refuse. Any of these counts as a possible refusal:
 *   - an if or conditional on the caller (or on a value derived from it, or
 *     from a helper that resolves it) with a return, throw or redirect in a
 *     branch, and any branch that answers 401 or "unauthorized";
 *   - a non-optional dereference of the caller, which crashes an anonymous call;
 *   - a call named like a thrower (requireX, assertX, ensureX, xOrThrow), or a
 *     checkX/verifyX/validateX whose answer is ignored;
 *   - a helper we can read that throws, redirects or answers 401/403, and a
 *     returned sign-in helper (`return handleSessionAuthentication()`);
 *   - the request handed to a helper we cannot read.
 * Wrapped (`export const GET = withAuth(...)`) and re-exported handlers are not
 * judged at all.
 */
// OPTIONS and HEAD answer preflight and probes, never data.
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const IDENTITY_NAME = /user|session|auth|admin|member|role|token|identity|viewer|account|access|permission|owner/i;
const THROWER_NAME = /^(require|assert|ensure|enforce|protect)([A-Z_]|$)|OrThrow$|OrRedirect$|OrFail$/;
const CHECKER_NAME = /^(check|verify|validate|authori[sz]e|guard)([A-Z_]|$)/;
const REFUSING_CALL = /^(redirect|permanentRedirect|notFound|unauthorized|forbidden)$/;
// A helper about the caller (named for it, or resolving it) refuses when it
// throws or redirects; any other helper handed the request or the caller only
// when it says so, because data helpers throw on failures that are not the
// caller's (corpus-b's sendMessage).
const REFUSAL_TEXT = /\bthrow\b|\b40[13]\b|unauthori[sz]ed|unauthenticated|forbidden|\bredirect\w*\s*\(|notFound\s*\(/i;
const CALLER_REFUSAL_TEXT = /\b40[13]\b|unauthori[sz]ed|unauthenticated|forbidden|\bredirect\w*\s*\(|notFound\s*\(/i;
const BENIGN_REQUEST_USE = /^(URL|NextResponse|Response|Request|Headers|console|JSON|String|Number|Object|Array|Promise)\b/;

type Body = (name: string) => string | null;

const lastName = (expr: ts.Expression): string | null =>
  ts.isIdentifier(expr) ? expr.text
  : ts.isPropertyAccessExpression(expr) ? expr.name.text
  : null;

const isFunctionLike = (n: ts.Node) =>
  ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n);

/** Every node in a handler body except the bodies of functions nested in it. */
function walk(node: ts.Node, visit: (n: ts.Node) => void) {
  ts.forEachChild(node, (child) => {
    visit(child);
    if (!isFunctionLike(child)) walk(child, visit);
  });
}

function bindingNames(name: ts.BindingName, out: Set<string>) {
  if (ts.isIdentifier(name)) out.add(name.text);
  else for (const el of name.elements) if (!ts.isOmittedExpression(el)) bindingNames(el.name, out);
}

function mentions(node: ts.Node, names: Set<string>): boolean {
  let hit = false;
  const visit = (n: ts.Node) => {
    if (hit) return;
    if (ts.isIdentifier(n) && names.has(n.text)) hit = true;
    else ts.forEachChild(n, visit);
  };
  visit(node);
  return hit;
}

function terminates(stmt: ts.Statement | undefined): boolean {
  if (!stmt) return false;
  let hit = false;
  const visit = (n: ts.Node) => {
    if (hit || isFunctionLike(n)) return;
    if (ts.isReturnStatement(n) || ts.isThrowStatement(n)) hit = true;
    else if (ts.isCallExpression(n) && REFUSING_CALL.test(lastName(n.expression) ?? "")) hit = true;
    else ts.forEachChild(n, visit);
  };
  visit(stmt);
  return hit;
}

/** A helper body that resolves or refuses the caller; a bare "user" or "role" is any data helper. */
const CALLER_BODY = /current_?user\s*\(|\bget_?user\s*\(|\bget_?session\s*\(|\bauth\s*\(|authRequired|unauthori[sz]ed|unauthenticated|\b401\b/i;

// A branch that answers like a sign-in refusal, whatever its condition tested.
// 401 and sign-in wording only: a 403 also answers feature flags and plan
// limits (corpus-b).
const BRANCH_REFUSAL = /\b401\b|unauthori[sz]ed|unauthenticated|not (?:signed|logged) in|sign[- ]?in|log[- ]?in|authRequired/i;
function refusalBranch(stmt: ts.Statement | undefined): boolean {
  return stmt !== undefined && terminates(stmt) && BRANCH_REFUSAL.test(stmt.getText());
}

/** A dereference inside a branch that already tested the same value. */
function guardedBy(node: ts.Node, name: string, stop: ts.Node): boolean {
  const named = new Set([name]);
  for (let child = node, p = node.parent; p && p !== stop; child = p, p = p.parent) {
    if (ts.isIfStatement(p) && child !== p.expression && mentions(p.expression, named)) return true;
    if (ts.isConditionalExpression(p) && child !== p.condition && mentions(p.condition, named)) return true;
    if (ts.isBinaryExpression(p) && child === p.right && mentions(p.left, named)) return true;
  }
  return false;
}

function judge(fn: ts.FunctionLikeDeclaration, body: Body): "refuses" | "unrefused" | "unknown" {
  if (!fn.body) return "unknown";
  const requestParam = fn.parameters[0] && ts.isIdentifier(fn.parameters[0].name) ? fn.parameters[0].name.text : null;
  const identity = new Set<string>();
  // Values from a helper whose body is about the caller (`resolveOwnedJob`
  // reading the current user). A test-and-return on one is a refusal; a
  // dereference of one is not, because data helpers mention users too.
  const tested = new Set<string>();
  const aboutCallerHelper = (call: ts.CallExpression) => {
    const helper = body(lastName(call.expression) ?? "");
    return helper !== null && CALLER_BODY.test(stripComments(helper));
  };
  const resolvesIdentity = (call: ts.CallExpression, text: string) => {
    const name = lastName(call.expression) ?? "";
    if (STRONG_USER_AUTH_RE.test(text) || IDENTITY_NAME.test(name) || CHECKER_NAME.test(name)) return true;
    const helper = body(name);
    return helper !== null && STRONG_USER_AUTH_RE.test(helper);
  };

  // Identity values and everything derived from them, to a fixpoint.
  const declarations: { names: Set<string>; init: ts.Expression }[] = [];
  walk(fn.body, (n) => {
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const names = new Set<string>();
      bindingNames(n.name, names);
      declarations.push({ names, init: n.initializer });
    } else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left)) {
      declarations.push({ names: new Set([n.left.text]), init: n.right });
    }
  });
  for (let grew = true; grew; ) {
    grew = false;
    for (const d of declarations) {
      if ([...d.names].every((x) => identity.has(x))) continue;
      let call: ts.CallExpression | undefined;
      const find = (n: ts.Node) => { if (!call && ts.isCallExpression(n)) call = n; else if (!call) ts.forEachChild(n, find); };
      find(d.init);
      if ((call && resolvesIdentity(call, d.init.getText())) || mentions(d.init, identity)) {
        for (const x of d.names) identity.add(x);
        grew = true;
      } else if (call && aboutCallerHelper(call)) {
        for (const x of d.names) tested.add(x);
      }
    }
  }

  for (const x of identity) tested.add(x);
  let verdict: "refuses" | "unknown" | null = null;
  const settle = (v: "refuses" | "unknown") => { if (verdict !== "refuses") verdict = v; };
  walk(fn.body, (n) => {
    if (ts.isIfStatement(n) && (mentions(n.expression, tested) || refusalBranch(n.thenStatement) || refusalBranch(n.elseStatement))
      && (terminates(n.thenStatement) || terminates(n.elseStatement))) settle("refuses");
    else if (ts.isConditionalExpression(n) && mentions(n.condition, identity) && ts.isReturnStatement(n.parent)) settle("refuses");
    else if ((ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) && !n.questionDotToken) {
      let target: ts.Expression = n.expression;
      while (ts.isNonNullExpression(target) || ts.isParenthesizedExpression(target)) target = target.expression;
      if (ts.isIdentifier(target) && identity.has(target.text) && !guardedBy(n, target.text, fn.body!)) settle("refuses");
    } else if (ts.isCallExpression(n)) {
      const name = lastName(n.expression) ?? "";
      const returned = ts.isReturnStatement(n.parent) || (ts.isAwaitExpression(n.parent) && ts.isReturnStatement(n.parent.parent));
      if (THROWER_NAME.test(name) || REFUSING_CALL.test(name)) settle("refuses");
      // `return handleSessionAuthentication()`: the helper's answer is the response.
      else if (returned && (IDENTITY_NAME.test(name) || CHECKER_NAME.test(name))) settle("refuses");
      else if (CHECKER_NAME.test(name) && ts.isExpressionStatement(n.parent.kind === ts.SyntaxKind.AwaitExpression ? n.parent.parent : n.parent)) settle("refuses");
      else {
        const raw = body(name);
        const helper = raw === null ? null : stripComments(raw);
        const aboutCaller = IDENTITY_NAME.test(name) || CHECKER_NAME.test(name) || (helper !== null && STRONG_USER_AUTH_RE.test(helper));
        const handedCaller = n.arguments.some((a) => mentions(a, identity) || (ts.isIdentifier(a) && a.text === requestParam));
        if (helper !== null && ((aboutCaller && REFUSAL_TEXT.test(helper)) || (handedCaller && CALLER_REFUSAL_TEXT.test(helper)))) settle("refuses");
        else if (helper === null && requestParam && !BENIGN_REQUEST_USE.test(n.expression.getText())
          && n.arguments.some((a) => ts.isIdentifier(a) && a.text === requestParam)
          && !STRONG_USER_AUTH_RE.test(n.getText())) settle("unknown");
      }
    }
  });
  return verdict ?? "unrefused";
}

/**
 * Methods whose handler we read in full and in which nothing refuses an
 * anonymous caller. `body(name)` returns the body of a function the route
 * calls (declared in the file or imported one hop), or null when unread.
 */
export function unrefusedMethods(content: string, body: Body): string[] {
  const sf = ts.createSourceFile("route.ts", content, ts.ScriptTarget.Latest, true);
  const out: string[] = [];
  const exported = (n: ts.Node) => ts.canHaveModifiers(n) && (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && exported(stmt) && stmt.name && METHODS.has(stmt.name.text)) {
      if (judge(stmt, body) === "unrefused") out.push(stmt.name.text);
    } else if (ts.isVariableStatement(stmt) && exported(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !METHODS.has(d.name.text) || !d.initializer) continue;
        const init = d.initializer;
        if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && judge(init, body) === "unrefused") out.push(d.name.text);
      }
    }
  }
  return out.sort();
}

const MIDDLEWARE_FILE = /^(.*?)(?:src\/)?(middleware|proxy)\.[cm]?[jt]s$/;
const MIDDLEWARE_AUTH = /clerkMiddleware|withAuth|next-auth\/middleware|getToken\s*\(|updateSession\s*\(|auth\.protect|authMiddleware/;

/** Next.js matcher source (`/dashboard/:path*`, `/((?!api/).*)`) as a regex. */
function matcherRegex(source: string): RegExp | null {
  try {
    return new RegExp(`^${source.replace(/:(\w+)\*/g, ".*").replace(/:(\w+)\+/g, ".+").replace(/:(\w+)/g, "[^/]+")}$`);
  } catch {
    return null;
  }
}

/**
 * A middleware (Next.js `middleware.ts` or, from Next 16, `proxy.ts`) of the
 * route's own application that checks the caller and whose matcher covers the
 * route path, so it may refuse an anonymous call before the handler runs. We
 * do not judge what it does inside; we say where it is.
 */
export function middlewareGap(routeFile: string, routePath: string, files: readonly { path: string; content: string }[]): string | null {
  const appRoot = routeFile.match(/^(.*?)(?:src\/)?(?:app|pages)\//)?.[1] ?? "";
  for (const f of files) {
    const m = f.path.match(MIDDLEWARE_FILE);
    if (!m || m[1] !== appRoot) continue;
    if (!MIDDLEWARE_AUTH.test(f.content) && !STRONG_USER_AUTH_RE.test(f.content)) continue;
    const config = f.content.match(/matcher\s*:\s*(\[[\s\S]*?\]|["'`][^"'`]*["'`])/);
    const sources = config ? [...config[1].matchAll(/["'`]([^"'`]+)["'`]/g)].map((s) => s[1]) : [];
    const covers = sources.length === 0 || sources.some((s) => matcherRegex(s)?.test(routePath) ?? true);
    if (covers) return `a middleware at ${f.path} checks the caller on this path and may refuse first`;
  }
  return null;
}

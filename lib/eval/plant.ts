import ts from "typescript";

/**
 * Planted holes for measuring recall (R1, Felipe 2026-10-07: "how are we
 * measuring recall?"). Precision labels only judge what ShipLock shows; a miss
 * is invisible unless the hole's truth is known in advance. A plant removes
 * exactly one real control from an exported route handler: a sign-in refusal
 * whose user the handler never reads afterwards (removing one that is read
 * would only crash the route, not open it), or an owner filter taken from the
 * caller's identity. The removed bytes and their offset are recorded so the
 * plant is reproducible against the pinned archive and refused on any other.
 * Measurement only: nothing in the product imports this.
 */
export type PlantOperator = "remove_auth_guard" | "remove_owner_scope";
export type Plant = { operator: PlantOperator; start: number; removed: string; attackClasses: string[] };

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const REFUSAL = /\b401\b|unauthori[sz]ed|UNAUTHORIZED|not authenticated|unauthenticated/i;
const NOT_FOUND = /\b404\b|not found/i;
const OWNER_NAME = /^(user_?id|owner_?id|author_?id|created_?by(_?id)?|creator_?id|profile_?id|account_?id)$/i;
/** An owner value read off the caller's identity: session.user.id, user.id, ctx.session.user.id. */
const CALLER_VALUE = /^(session|user|currentUser|authUser|me|ctx\.session|ctx\.user|auth)\b[\w?.!]*$/;
const IDENTITY_CALL = /\b(auth|getServerSession|getSession|getUser|currentUser|getCurrentUser|getAuth|requireUser|requireAuth)\s*\(/;
const REQUEST_INPUT = /\b(req|request|body|params|searchParams|query|input|formData)\b/;

/** Whether the handler declared this bare name from the caller's identity, never from the request. */
function callerLocal(name: string, fn: ts.FunctionLikeDeclaration, sf: ts.SourceFile): boolean {
  let fromCaller = false, fromRequest = false;
  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const names = ts.isIdentifier(n.name) ? [n.name.text]
        : n.name.elements.flatMap((e) => (ts.isBindingElement(e) && ts.isIdentifier(e.name) ? [e.name.text] : []));
      if (names.includes(name)) {
        const init = n.initializer.getText(sf);
        if (REQUEST_INPUT.test(init)) fromRequest = true;
        else if (IDENTITY_CALL.test(init) || CALLER_VALUE.test(init)) fromCaller = true;
      }
    }
    ts.forEachChild(n, visit);
  };
  if (fn.body) visit(fn.body);
  return fromCaller && !fromRequest;
}
const callerValue = (expr: ts.Expression, fn: ts.FunctionLikeDeclaration, sf: ts.SourceFile) =>
  CALLER_VALUE.test(expr.getText(sf)) || (ts.isIdentifier(expr) && callerLocal(expr.text, fn, sf));

const exported = (mods: ts.NodeArray<ts.ModifierLike> | undefined, kind: ts.SyntaxKind) => Boolean(mods?.some((m) => m.kind === kind));

/** The exported HTTP handler each node sits in, or null. A pages/api file's default export handles every method. */
function handlerOf(node: ts.Node, defaultExportHandles: boolean): ts.FunctionLikeDeclaration | null {
  for (let n: ts.Node | undefined = node; n; n = n.parent) {
    if (defaultExportHandles && ts.isFunctionDeclaration(n) && exported(n.modifiers, ts.SyntaxKind.ExportKeyword)
      && exported(n.modifiers, ts.SyntaxKind.DefaultKeyword)) return n;
    if (defaultExportHandles && (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) && ts.isExportAssignment(n.parent)) return n;
    if (ts.isFunctionDeclaration(n) && n.name && HTTP_METHODS.has(n.name.text) && n.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) return n;
    if ((ts.isArrowFunction(n) || ts.isFunctionExpression(n)) && ts.isVariableDeclaration(n.parent) && ts.isIdentifier(n.parent.name)
      && HTTP_METHODS.has(n.parent.name.text) && ts.isVariableDeclarationList(n.parent.parent) && ts.isVariableStatement(n.parent.parent.parent)
      && n.parent.parent.parent.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) return n;
  }
  return null;
}

/** The identifier at the root of `!x`, `!x.y`, `!x?.y`, or `!a || !a.b` on one root; else null. */
function guardedRoot(cond: ts.Expression): string | null {
  if (ts.isParenthesizedExpression(cond)) return guardedRoot(cond.expression);
  if (ts.isBinaryExpression(cond) && cond.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
    const a = guardedRoot(cond.left), b = guardedRoot(cond.right);
    return a && a === b ? a : null;
  }
  if (!ts.isPrefixUnaryExpression(cond) || cond.operator !== ts.SyntaxKind.ExclamationToken) return null;
  let e: ts.Expression = cond.operand;
  while (ts.isPropertyAccessExpression(e) || ts.isNonNullExpression(e) || ts.isParenthesizedExpression(e)) e = e.expression;
  return ts.isIdentifier(e) ? e.text : null;
}

const refuses = (stmt: ts.Statement, sf: ts.SourceFile): boolean => {
  let found = false;
  const visit = (n: ts.Node) => {
    if ((ts.isReturnStatement(n) || ts.isThrowStatement(n)) && REFUSAL.test(n.getText(sf))) found = true;
    if (!found) ts.forEachChild(n, visit);
  };
  visit(stmt);
  // A missing row is not a missing control: "not found or unauthorized" with a 404 is a lookup.
  return found && !NOT_FOUND.test(stmt.getText(sf));
};

function readsAfter(name: string, after: number, fn: ts.FunctionLikeDeclaration): boolean {
  let used = false;
  const visit = (n: ts.Node) => {
    if (used) return;
    if (ts.isIdentifier(n) && n.text === name && n.getStart() >= after
      && !(ts.isPropertyAccessExpression(n.parent) && n.parent.name === n)
      && !(ts.isPropertyAssignment(n.parent) && n.parent.name === n)) used = true;
    ts.forEachChild(n, visit);
  };
  if (fn.body) visit(fn.body);
  return used;
}

/** Text to remove for one element of a comma list: the element and one adjoining comma. */
function listRemoval(elements: ts.NodeArray<ts.Node>, i: number, sf: ts.SourceFile): { start: number; end: number } {
  const node = elements[i];
  if (i + 1 < elements.length) return { start: node.getStart(sf), end: elements[i + 1].getStart(sf) };
  if (i > 0) return { start: elements[i - 1].getEnd(), end: node.getEnd() };
  return { start: node.getStart(sf), end: node.getEnd() };
}

/** Reads that return one row: without another filter they error on many rows instead of leaking one. */
const SINGLE_ROW = /\.(single|maybeSingle)\s*\(|^(findFirst|findUnique|findFirstOrThrow|findUniqueOrThrow)$/;

/** The outermost call of a fluent chain this call sits in (supabase.from(...).select(...).eq(...).single()). */
function chainTop(n: ts.Node): ts.Node {
  let top = n;
  while (ts.isPropertyAccessExpression(top.parent) || (ts.isCallExpression(top.parent) && top.parent.expression === top)) top = top.parent;
  return top;
}

/** Whether removing this .eq leaves a hole: the chain lists rows, or still filters on something else. */
function eqRemovalOpens(call: ts.CallExpression, sf: ts.SourceFile): boolean {
  const chain = chainTop(call).getText(sf);
  if (!SINGLE_ROW.test(chain)) return true;
  return (chain.match(/\.(eq|match|in|filter)\s*\(/g) ?? []).length > 1;
}

/** Whether removing this property leaves a hole: the where keeps another filter, or the call reads or writes many rows. */
function propertyRemovalOpens(prop: ts.ObjectLiteralElementLike): boolean {
  const where = prop.parent as ts.ObjectLiteralExpression;
  if (where.properties.length > 1) return true;
  for (let n: ts.Node | undefined = where.parent; n; n = n.parent) {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) return !SINGLE_ROW.test(n.expression.name.text);
  }
  return false;
}

const insideWhere = (node: ts.Node): boolean => {
  for (let n: ts.Node | undefined = node.parent, depth = 0; n && depth < 6; n = n.parent, depth++) {
    if (ts.isPropertyAssignment(n) && n.name.getText() === "where") return true;
  }
  return false;
};

/** Where a known bug can be planted in a route handler: a sign-in guard
 * or an owner scope whose removal yields a known, labeled vulnerability. */
export function findPlants(source: string, options: { defaultExportHandles?: boolean } = {}): Plant[] {
  const sf = ts.createSourceFile("route.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const plants: Plant[] = [];
  const add = (operator: PlantOperator, start: number, end: number) => plants.push({ operator, start, removed: source.slice(start, end),
    // A removed guard may be a sign-in or a role check, so either class names it.
    attackClasses: operator === "remove_auth_guard" ? ["missing_authentication", "missing_authorization"] : ["missing_authorization"] });

  const visit = (n: ts.Node) => {
    const fn = handlerOf(n, options.defaultExportHandles ?? false);
    if (fn && ts.isIfStatement(n) && !n.elseStatement && refuses(n.thenStatement, sf)) {
      const root = guardedRoot(n.expression);
      if (root && !readsAfter(root, n.getEnd(), fn)) add("remove_auth_guard", n.getStart(sf), n.getEnd());
    }
    if (fn && ts.isPropertyAssignment(n) && OWNER_NAME.test(n.name.getText(sf)) && callerValue(n.initializer, fn, sf)
      && ts.isObjectLiteralExpression(n.parent) && insideWhere(n) && propertyRemovalOpens(n)) {
      const r = listRemoval(n.parent.properties, n.parent.properties.indexOf(n), sf);
      add("remove_owner_scope", r.start, r.end);
    }
    if (fn && ts.isShorthandPropertyAssignment(n) && OWNER_NAME.test(n.name.text) && callerLocal(n.name.text, fn, sf)
      && ts.isObjectLiteralExpression(n.parent) && insideWhere(n) && propertyRemovalOpens(n)) {
      const r = listRemoval(n.parent.properties, n.parent.properties.indexOf(n), sf);
      add("remove_owner_scope", r.start, r.end);
    }
    // Supabase: .eq("user_id", user.id) on a query chain.
    if (fn && ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "eq"
      && n.arguments.length === 2 && ts.isStringLiteral(n.arguments[0]) && OWNER_NAME.test(n.arguments[0].text)
      && callerValue(n.arguments[1], fn, sf) && eqRemovalOpens(n, sf)) {
      add("remove_owner_scope", n.expression.expression.getEnd(), n.getEnd());
    }
    // Drizzle: and(..., eq(t.userId, session.user.id), ...).
    if (fn && ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "eq" && n.arguments.length === 2
      && ts.isPropertyAccessExpression(n.arguments[0]) && OWNER_NAME.test(n.arguments[0].name.text)
      && callerValue(n.arguments[1], fn, sf)
      && ts.isCallExpression(n.parent) && ts.isIdentifier(n.parent.expression) && n.parent.expression.text === "and" && n.parent.arguments.length >= 2) {
      const r = listRemoval(n.parent.arguments, n.parent.arguments.indexOf(n), sf);
      add("remove_owner_scope", r.start, r.end);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  // A plant must leave a file that still parses.
  return plants.filter((p) => syntaxErrors(applyPlant(source, p)) <= syntaxErrors(source));
}

function syntaxErrors(source: string): number {
  return (ts.transpileModule(source, { reportDiagnostics: true, fileName: "route.tsx" }).diagnostics ?? []).length;
}

/** The source with the plant's bytes removed; refuses if they are not at the recorded offset. */
export function applyPlant(source: string, plant: Pick<Plant, "start" | "removed">): string {
  if (source.slice(plant.start, plant.start + plant.removed.length) !== plant.removed) {
    throw new Error("Plant does not match this source (different archive or offset)");
  }
  return source.slice(0, plant.start) + source.slice(plant.start + plant.removed.length);
}

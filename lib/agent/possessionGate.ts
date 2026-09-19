import ts from "typescript";
import type { RepoFile } from "@/lib/deep/githubScan";
import type { RouteFact } from "@/lib/graph/routeInventory";

/**
 * POSSESSION GATES: A VOCABULARY FIX, NOT A DETECTOR.
 *
 * Six of corpus-b's eight admitted criticals were false (docs/STATE.md,
 * HEADLINE), and five share one mechanism: the endpoint admits whoever presents
 * a row id, looks the row up, and refuses the request unless the row also
 * matches another resource the same request names. That is a share-link
 * design. The only sentence the product had for it was `missing_authentication`,
 * CRITICAL, and that sentence is wrong.
 *
 * This module reads what is already readable about such a gate and nothing
 * more, so the finding can say the true thing at the right severity. It does
 * NOT decide whether possession-based access is safe, and it never removes a
 * route from anything. The detector finds exactly what it found before; a route
 * with a readable gate is RE-WORDED, never suppressed.
 *
 * THE BAR, AND WHY IT IS NARROW ON PURPOSE.
 *
 * Moving a real critical into an informational class is the fail-open
 * direction, so every condition below is a refusal and anything unreadable
 * leaves the route a critical:
 *
 *  1. The route is anonymous by facts we READ (identity readable, no session,
 *     no machine gate). An unreadable identity is never a reason to downgrade.
 *
 *  2. Every exported handler is a function written in the route file. A
 *     wrapper, a re-export or a factory call is not followed -- this module does
 *     not touch the wrapper asymmetry, and a handler we cannot read has no gate.
 *
 *  3. THE BINDING IS REQUIRED. A single-record Prisma lookup keyed on a
 *     request-supplied id must ALSO be constrained by at least one other
 *     resource: another request-supplied value in the same `where`, a field of
 *     a row found earlier the same way, or a `row.field !== requestValue`
 *     disjunct in the null check.
 *
 *     This is the condition that keeps corpus-b's
 *     /api/teams/[teamId]/documents/document-processing-status a critical. It
 *     takes one id, looks it up by primary key and 404s on null -- every other
 *     test here passes -- and it is a CONFIRMED TRUE POSITIVE: a forgotten auth
 *     check whose siblings authenticate. Nothing in its dataflow says so. A
 *     one-id lookup is exactly the shape of an object id used as its own access
 *     control, so a one-id lookup is never a possession gate, and
 *     `possessionGate.test.ts` pins it.
 *
 *     It also means a foreign-key-only write does not qualify.
 *     corpus-b's /api/record_reaction creates a row whose `viewId` must exist,
 *     and names no second resource. The database constraint is real, but it is
 *     a one-id check by another route, and admitting it would admit
 *     document-processing-status by the same argument. It stays a critical.
 *
 *     Two caller-supplied ids that must agree are CONSISTENCY, not ownership
 *     (docs/audit/adjudication.md). The rendered finding says exactly that and
 *     claims no authorization.
 *
 *  4. The null check must immediately follow the lookup and end in `return`.
 *     A `throw` can be swallowed by a surrounding catch.
 *
 *  5. Nothing may touch data outside the region the gate dominates. Every call
 *     outside it must be inert: a response written through the handler's own
 *     response object, a schema validation, the request-body read, console.
 *     This IS a list, and lists have failed five times in this codebase. It
 *     fails CLOSED: an unlisted call means no gate, so the route stays a
 *     critical, which costs a false critical rather than a real one.
 *
 *  6. THE ID MUST HAVE A READABLE, RANDOM MINT. See `mintOf`. An autoincrement
 *     id is never a possession gate. A slug is never a possession gate. An id
 *     with no readable default is never a possession gate. The lookup reader is
 *     Prisma-only today, so a Drizzle or SQL schema yields no gate at all.
 *
 * WHAT IS NEVER READ, AND IS SAID IN EVERY FINDING: whether the id is shown to
 * anyone other than whoever holds it. That is the half of a capability design
 * the customer can see and we cannot.
 */

export interface PossessionMint {
  /** The default expression as written in the schema. */
  expression: string;
  /** Plain statement of how guessable the id is. */
  strength: string;
  /** Where the schema says it. */
  file: string;
  line: number;
}

export interface PossessionBinding {
  /** The column on the looked-up row that must match. */
  field: string;
  /** The model that column refers to, when the schema declares the relation. */
  resource: string | null;
  /** Where the matched value came from, in words. */
  source: string;
  file: string;
  line: number;
}

export interface PossessionGate {
  path: string;
  file: string;
  /** The Prisma model looked up, as declared in the schema. */
  model: string;
  /** The id column the request value keys. */
  field: string;
  /** The request-supplied name, as the handler binds it. */
  param: string;
  /** Where the request value came from, in words. */
  paramSource: string;
  lookupLine: number;
  bindings: PossessionBinding[];
  mint: PossessionMint;
}

// ─── Schema ──────────────────────────────────────────────────────────────────

interface SchemaField {
  name: string;
  type: string;
  isId: boolean;
  isUnique: boolean;
  defaultExpr: string | null;
  file: string;
  line: number;
}

interface SchemaModel {
  name: string;
  fields: Map<string, SchemaField>;
  /** Relation scalar -> related model: `link Link @relation(fields: [linkId])`. */
  relations: Map<string, string>;
}

/** `@default(cuid())` -> `cuid()`, balancing nested parentheses. */
function defaultOf(attrs: string): string | null {
  const at = attrs.indexOf("@default(");
  if (at === -1) return null;
  let depth = 0;
  const start = at + "@default(".length;
  for (let i = start; i < attrs.length; i++) {
    const c = attrs[i];
    if (c === "(") depth++;
    else if (c === ")") {
      if (depth === 0) return attrs.slice(start, i).trim();
      depth--;
    }
  }
  return null;
}

/**
 * Prisma models from every `.prisma` file. A model declared twice with any
 * difference is dropped rather than guessed between: a monorepo with two
 * schemas that disagree has no readable mint.
 */
export function readPrismaModels(files: Iterable<RepoFile>): Map<string, SchemaModel> {
  const models = new Map<string, SchemaModel>();
  const conflicted = new Set<string>();
  for (const file of files) {
    if (!file.path.endsWith(".prisma")) continue;
    const lines = file.content.split("\n");
    let current: SchemaModel | null = null;
    lines.forEach((raw, index) => {
      const line = raw.replace(/\/\/.*$/, "").trim();
      const open = line.match(/^model\s+(\w+)\s*\{/);
      if (open) {
        current = { name: open[1], fields: new Map(), relations: new Map() };
        return;
      }
      if (!current) return;
      if (line.startsWith("}")) {
        const model: SchemaModel = current;
        const existing = models.get(model.name);
        if (existing && !sameModel(existing, model)) conflicted.add(model.name);
        else if (!existing) models.set(model.name, model);
        current = null;
        return;
      }
      const field = line.match(/^(\w+)\s+(\w+)(\[\])?\??\s*(.*)$/);
      if (!field || line.startsWith("@@")) return;
      const [, name, type, , attrs] = field;
      const model: SchemaModel = current;
      model.fields.set(name, {
        name,
        type,
        isId: /(^|\s)@id\b/.test(attrs),
        isUnique: /(^|\s)@unique\b/.test(attrs),
        defaultExpr: defaultOf(attrs),
        file: file.path,
        line: index + 1,
      });
      const relation = attrs.match(/@relation\([^)]*fields:\s*\[\s*(\w+)\s*\]/);
      if (relation) model.relations.set(relation[1], type);
    });
  }
  for (const name of conflicted) models.delete(name);
  return models;
}

function sameModel(a: SchemaModel, b: SchemaModel): boolean {
  if (a.fields.size !== b.fields.size) return false;
  for (const [name, f] of a.fields) {
    const g = b.fields.get(name);
    if (!g || g.type !== f.type || g.isId !== f.isId || g.isUnique !== f.isUnique || g.defaultExpr !== f.defaultExpr) return false;
  }
  return true;
}

/**
 * RULE: A POSSESSION GATE NEEDS A RANDOM MINT THE SCHEMA STATES.
 *
 * Returns null -- never a gate -- for:
 *   - `autoincrement()`, `sequence()` and every other non-random default: the
 *     next id is the last id plus one;
 *   - a column with no default at all, which includes every slug: whatever
 *     wrote the value is application code we did not read;
 *   - any default not listed below: unrecognised is unreadable, not random.
 *
 * Strengths are stated from the generators' published formats, and only where
 * the format fixes the number.
 */
export function mintOf(expression: string | null): string | null {
  if (!expression) return null;
  const e = expression.replace(/\s+/g, "");
  if (e === "cuid()" || e === "cuid(1)") {
    return "a version 1 cuid: a timestamp, a counter and a host fingerprint around roughly 41 random bits. Hard to enumerate, and not a secret token";
  }
  if (e === "cuid(2)") return "a version 2 cuid, derived from a cryptographic hash of random input";
  if (e === "uuid()" || e === "uuid(4)" || e === 'dbgenerated("gen_random_uuid()")') {
    return "a version 4 UUID: 122 random bits";
  }
  if (e === "uuid(7)") return "a version 7 UUID: a millisecond timestamp followed by 74 random bits";
  if (e === "nanoid()") return "a 21 character nanoid: about 126 random bits";
  if (e === "ulid()") return "a ULID: a millisecond timestamp followed by 80 random bits";
  return null;
}

// ─── Handler reading ─────────────────────────────────────────────────────────

const METHOD_EXPORTS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === kind);
}

function unwrap(expr: ts.Expression): ts.Expression {
  let cur = expr;
  while (
    ts.isAwaitExpression(cur) ||
    ts.isParenthesizedExpression(cur) ||
    ts.isAsExpression(cur) ||
    ts.isNonNullExpression(cur) ||
    ts.isSatisfiesExpression(cur) ||
    ts.isTypeAssertionExpression(cur)
  ) {
    cur = cur.expression;
  }
  return cur;
}

type HandlerFn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

/**
 * Every handler the route file exports, or null when any export is something we
 * do not read as a function body here (a wrapper call, a re-export, an import).
 */
function handlersOf(sf: ts.SourceFile): HandlerFn[] | null {
  const locals = new Map<string, HandlerFn>();
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body) locals.set(stmt.name.text, stmt);
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer) {
          const init = unwrap(d.initializer);
          if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && ts.isBlock(init.body)) locals.set(d.name.text, init);
        }
      }
    }
  }

  const found = new Set<HandlerFn>();
  let unreadable = false;
  const byName = (name: string): void => {
    const fn = locals.get(name);
    if (fn) found.add(fn);
    else unreadable = true;
  };

  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && hasModifier(stmt, ts.SyntaxKind.ExportKeyword)) {
      const isDefault = hasModifier(stmt, ts.SyntaxKind.DefaultKeyword);
      if (isDefault || (stmt.name && METHOD_EXPORTS.has(stmt.name.text))) {
        if (stmt.body) found.add(stmt);
        else unreadable = true;
      }
    } else if (ts.isVariableStatement(stmt) && hasModifier(stmt, ts.SyntaxKind.ExportKeyword)) {
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !METHOD_EXPORTS.has(d.name.text) || !d.initializer) continue;
        const init = unwrap(d.initializer);
        if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && ts.isBlock(init.body)) found.add(init);
        else if (ts.isIdentifier(init)) byName(init.text);
        else unreadable = true;
      }
    } else if (ts.isExportAssignment(stmt)) {
      const e = unwrap(stmt.expression);
      if ((ts.isArrowFunction(e) || ts.isFunctionExpression(e)) && ts.isBlock(e.body)) found.add(e);
      else if (ts.isIdentifier(e)) byName(e.text);
      else unreadable = true;
    } else if (ts.isExportDeclaration(stmt)) {
      // `export { default } from "..."`, `export { handler as GET }`: not read here.
      const names = stmt.exportClause && ts.isNamedExports(stmt.exportClause) ? stmt.exportClause.elements : [];
      if (stmt.moduleSpecifier || names.some((n) => n.name.text === "default" || METHOD_EXPORTS.has(n.name.text))) unreadable = true;
    }
  }
  if (unreadable || found.size === 0) return null;
  return [...found];
}

function paramName(fn: HandlerFn, index: number): string | null {
  const p = fn.parameters[index];
  return p && ts.isIdentifier(p.name) ? p.name.text : null;
}

/** Names bound from the request, with where each came from. */
function requestNames(fn: HandlerFn, file: string): Map<string, string> {
  const req = paramName(fn, 0);
  const out = new Map<string, string>();
  const holders = new Map<string, string>();
  const segments = new Set([...file.matchAll(/\[(?:\.\.\.)?(\w+)\]/g)].map((m) => m[1]));

  // `params` destructured in the signature: `(req, { params })`.
  const second = fn.parameters[1];
  const paramsNames = new Set<string>();
  if (second && ts.isObjectBindingPattern(second.name)) {
    for (const el of second.name.elements) if (ts.isIdentifier(el.name) && el.name.text === "params") paramsNames.add("params");
  }
  const secondName = paramName(fn, 1);

  const sourceOf = (init: ts.Expression): string | null => {
    const e = unwrap(init);
    if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
      if (e.expression.text === req && e.name.text === "body") return "the request body";
      if (e.expression.text === req && e.name.text === "query") return "the request query";
      if (secondName && e.expression.text === secondName && e.name.text === "params") return "the URL path";
    }
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && ts.isIdentifier(e.expression.expression)) {
      if (e.expression.expression.text === req && e.expression.name.text === "json" && e.arguments.length === 0) return "the request body";
    }
    if (ts.isIdentifier(e) && paramsNames.has(e.text)) return "the URL path";
    if (ts.isIdentifier(e) && holders.has(e.text)) return holders.get(e.text)!;
    return null;
  };

  const visit = (node: ts.Node): void => {
    if (node !== fn && ts.isFunctionLike(node)) return;
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const source = sourceOf(node.initializer);
      if (source) {
        if (ts.isIdentifier(node.name)) holders.set(node.name.text, source);
        else if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            if (el.dotDotDotToken || !ts.isIdentifier(el.name)) continue;
            const key = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            // A pages-router dynamic segment arrives on req.query under its own name.
            const where = source === "the request query" && segments.has(key) ? "the URL path" : source;
            out.set(el.name.text, where);
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  if (fn.body) visit(fn.body);

  // A name assigned again later is not the request value any more.
  const reassigned = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      out.delete(node.left.text);
    }
    ts.forEachChild(node, reassigned);
  };
  if (fn.body) reassigned(fn.body);
  return out;
}

interface Lookup {
  statement: ts.VariableStatement;
  variable: string;
  model: SchemaModel;
  where: ts.ObjectLiteralExpression;
  line: number;
}

/** `const v = await prisma.model.findUnique|findFirst({ where: {...} })`. */
function lookupAt(stmt: ts.Statement, models: Map<string, SchemaModel>, sf: ts.SourceFile): Lookup | null {
  if (!ts.isVariableStatement(stmt) || stmt.declarationList.declarations.length !== 1) return null;
  const d = stmt.declarationList.declarations[0];
  if (!ts.isIdentifier(d.name) || !d.initializer || !ts.isAwaitExpression(d.initializer)) return null;
  const call = unwrap(d.initializer);
  if (!ts.isCallExpression(call) || !ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text;
  if (method !== "findUnique" && method !== "findFirst") return null;
  const accessor = call.expression.expression;
  if (!ts.isPropertyAccessExpression(accessor) || !ts.isIdentifier(accessor.expression) || accessor.expression.text !== "prisma") return null;
  const modelName = accessor.name.text.charAt(0).toUpperCase() + accessor.name.text.slice(1);
  const model = models.get(modelName);
  const arg = call.arguments[0];
  if (!model || !arg || !ts.isObjectLiteralExpression(arg)) return null;
  const whereProp = arg.properties.find(
    (p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === "where",
  );
  if (!whereProp || !ts.isObjectLiteralExpression(whereProp.initializer)) return null;
  return {
    statement: stmt,
    variable: d.name.text,
    model,
    where: whereProp.initializer,
    line: sf.getLineAndCharacterOfPosition(stmt.getStart(sf)).line + 1,
  };
}

/** `if (!v) return …` or `if (!v || …) { …; return … }`, with no else. */
function terminatingNullCheck(stmt: ts.Statement | undefined, variable: string): ts.IfStatement | null {
  if (!stmt || !ts.isIfStatement(stmt) || stmt.elseStatement) return null;
  const disjuncts: ts.Expression[] = [];
  const split = (e: ts.Expression): void => {
    const x = ts.isParenthesizedExpression(e) ? e.expression : e;
    if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      split(x.left);
      split(x.right);
    } else disjuncts.push(x);
  };
  split(stmt.expression);
  const negates = disjuncts.some(
    (d) => ts.isPrefixUnaryExpression(d) && d.operator === ts.SyntaxKind.ExclamationToken && ts.isIdentifier(d.operand) && d.operand.text === variable,
  );
  if (!negates) return null;
  const then = stmt.thenStatement;
  const last = ts.isBlock(then) ? then.statements[then.statements.length - 1] : then;
  return last && ts.isReturnStatement(last) ? stmt : null;
}

function fieldKey(p: ts.ObjectLiteralElementLike): string | null {
  if (ts.isShorthandPropertyAssignment(p)) return p.name.text;
  if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) return p.name.text;
  return null;
}

function fieldValue(p: ts.ObjectLiteralElementLike): ts.Expression | null {
  if (ts.isShorthandPropertyAssignment(p)) return p.name;
  if (ts.isPropertyAssignment(p)) return unwrap(p.initializer);
  return null;
}

/** The id column a request value keys, when the schema gives it a random mint. */
function tokenOf(lookup: Lookup, names: Map<string, string>): { field: SchemaField; param: string; source: string; mint: string } | null {
  for (const p of lookup.where.properties) {
    const key = fieldKey(p);
    const value = fieldValue(p);
    if (!key || !value || !ts.isIdentifier(value) || !names.has(value.text)) continue;
    const field = lookup.model.fields.get(key);
    if (!field || !(field.isId || field.isUnique)) continue;
    const mint = mintOf(field.defaultExpr);
    if (!mint) continue;
    return { field, param: value.text, source: names.get(value.text)!, mint };
  }
  return null;
}

type GateBody = Omit<PossessionGate, "path" | "file">;

/**
 * One handler. Returns the gate, `"inert"` when the handler touches nothing at
 * all (an OPTIONS responder), or null.
 */
function evaluateHandler(fn: HandlerFn, file: string, sf: ts.SourceFile, models: Map<string, SchemaModel>): GateBody | "inert" | null {
  if (!fn.body || !ts.isBlock(fn.body)) return null;
  const names = requestNames(fn, file);
  const res = paramName(fn, 1);

  // Every statement list in the handler, outermost first, excluding nested functions.
  const lists: ts.NodeArray<ts.Statement>[] = [];
  const collect = (node: ts.Node): void => {
    if (node !== fn && ts.isFunctionLike(node)) return;
    if (ts.isBlock(node)) lists.push(node.statements);
    ts.forEachChild(node, collect);
  };
  collect(fn.body);

  let gate: GateBody | null = null;
  let region: ts.Node[] = [];
  let preludes: ts.Node[] = [];
  let preludeRows: string[] = [];

  for (const list of lists) {
    // Rows found earlier in this list by a random-mint id and null-checked.
    const rows = new Map<string, { lookup: Lookup; param: string }>();
    const prelude: ts.Node[] = [];
    for (let i = 0; i < list.length && !gate; i++) {
      const lookup = lookupAt(list[i], models, sf);
      if (!lookup) continue;
      const check = terminatingNullCheck(list[i + 1], lookup.variable);
      const token = tokenOf(lookup, names);
      if (!check || !token) continue;

      const bindings: PossessionBinding[] = [];
      for (const p of lookup.where.properties) {
        const key = fieldKey(p);
        const value = fieldValue(p);
        if (!key || !value || key === token.field.name) continue;
        // A scalar column of this model. A relation field (typed as another
        // model) is a nested filter, not a value to match.
        const column = lookup.model.fields.get(key);
        if (!column || models.has(column.type)) continue;
        const line = sf.getLineAndCharacterOfPosition(p.getStart(sf)).line + 1;
        if (ts.isIdentifier(value) && names.has(value.text) && value.text !== token.param) {
          bindings.push({ field: key, resource: lookup.model.relations.get(key) ?? null, source: `${value.text} from ${names.get(value.text)}`, file, line });
        } else if (
          ts.isPropertyAccessExpression(value) &&
          ts.isIdentifier(value.expression) &&
          rows.has(value.expression.text)
        ) {
          const row = rows.get(value.expression.text)!;
          bindings.push({
            field: key,
            resource: lookup.model.relations.get(key) ?? null,
            source: `the ${value.name.text} of the ${row.lookup.model.name} found by ${row.param}`,
            file,
            line,
          });
        }
      }
      // `row.field !== requestValue` inside the null check binds as well.
      const split = (e: ts.Expression): void => {
        const x = ts.isParenthesizedExpression(e) ? e.expression : e;
        if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.BarBarToken) { split(x.left); split(x.right); return; }
        if (
          ts.isBinaryExpression(x) &&
          (x.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken || x.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken)
        ) {
          const [l, r] = [unwrap(x.left), unwrap(x.right)];
          const sides: [ts.Expression, ts.Expression][] = [[l, r], [r, l]];
          for (const [rowSide, reqSide] of sides) {
            if (
              ts.isPropertyAccessExpression(rowSide) &&
              ts.isIdentifier(rowSide.expression) &&
              rowSide.expression.text === lookup.variable &&
              lookup.model.fields.has(rowSide.name.text) &&
              ts.isIdentifier(reqSide) &&
              names.has(reqSide.text) &&
              reqSide.text !== token.param
            ) {
              bindings.push({
                field: rowSide.name.text,
                resource: lookup.model.relations.get(rowSide.name.text) ?? null,
                source: `${reqSide.text} from ${names.get(reqSide.text)}`,
                file,
                line: sf.getLineAndCharacterOfPosition(x.getStart(sf)).line + 1,
              });
            }
          }
        }
      };
      split(check.expression);

      if (bindings.length === 0) {
        // RULE 3. A one-id lookup is not a gate. It may still constrain a LATER
        // lookup as the row that lookup is bound to.
        rows.set(lookup.variable, { lookup, param: token.param });
        prelude.push(list[i], list[i + 1]);
        continue;
      }

      gate = {
        model: lookup.model.name,
        field: token.field.name,
        param: token.param,
        paramSource: token.source,
        lookupLine: lookup.line,
        bindings,
        mint: { expression: token.field.defaultExpr!, strength: token.mint, file: token.field.file, line: token.field.line },
      };
      preludes = [...prelude, list[i], list[i + 1]];
      preludeRows = [...rows.keys()];
      region = dominatedRegion(list, i + 1);
    }
    if (gate) break;
  }

  const within = (node: ts.Node, roots: ts.Node[]): boolean => {
    for (let p: ts.Node | undefined = node; p && p !== fn; p = p.parent) if (roots.includes(p)) return true;
    return false;
  };

  // RULE 5. Every call outside the dominated region must be inert.
  let touchesData = false;
  let clean = true;
  const inert = (call: ts.CallExpression): boolean => {
    let root: ts.Expression = call.expression;
    while (ts.isPropertyAccessExpression(root) || ts.isCallExpression(root)) root = ts.isCallExpression(root) ? root.expression : root.expression;
    const text = call.expression.getText(sf);
    if (res && ts.isIdentifier(root) && root.text === res) return true;
    if (/^(NextResponse|Response)\s*\.\s*json$/.test(text)) return true;
    if (/\.\s*(safeParse|parse)$/.test(text) && !/^JSON\s*\./.test(text)) return true;
    if (/^console\s*\./.test(text)) return true;
    const req = paramName(fn, 0);
    if (req && new RegExp(`^${req}\\s*\\.\\s*json$`).test(text)) return true;
    return false;
  };
  const scan = (node: ts.Node): void => {
    if (!clean) return;
    if (ts.isCallExpression(node)) {
      const covered = within(node, region) || within(node, preludes);
      if (!covered && !inert(node)) clean = false;
      if (!inert(node)) touchesData = true;
    }
    // A row found before the gate is not released before the gate.
    if (ts.isIdentifier(node) && preludeRows.includes(node.text) && !within(node, region) && !within(node, preludes)) clean = false;
    ts.forEachChild(node, scan);
  };
  scan(fn.body);

  if (!clean) return null;
  if (!gate) return touchesData ? null : "inert";
  return gate;
}

/**
 * The statements the gate's null check dominates: everything after it in its
 * own list, and -- when that list is a try block whose catch always returns --
 * everything after the try in the enclosing list, climbing while that holds.
 * An `if` block stops the climb: code after it runs when the condition is false.
 */
function dominatedRegion(list: ts.NodeArray<ts.Statement>, checkIndex: number): ts.Node[] {
  const region: ts.Node[] = list.slice(checkIndex + 1);
  let block: ts.Node | undefined = list[0]?.parent;
  while (block && ts.isBlock(block) && block.parent && ts.isTryStatement(block.parent) && block.parent.tryBlock === block) {
    const tryStmt: ts.TryStatement = block.parent;
    if (tryStmt.finallyBlock) break;
    const catchBody = tryStmt.catchClause?.block.statements;
    if (catchBody && !(catchBody.length > 0 && ts.isReturnStatement(catchBody[catchBody.length - 1]))) break;
    const parent: ts.Node = tryStmt.parent;
    if (!parent || !ts.isBlock(parent)) break;
    const index = parent.statements.indexOf(tryStmt);
    region.push(...parent.statements.slice(index + 1));
    block = parent;
  }
  return region;
}

/**
 * Possession gates for one repository, keyed by route path. A route appears
 * only when every handler it exports was read and at least one carries a gate
 * by every rule above.
 */
export function possessionGates(routes: RouteFact[], byPath: Map<string, RepoFile>): Map<string, PossessionGate> {
  const out = new Map<string, PossessionGate>();
  const models = readPrismaModels(byPath.values());
  if (models.size === 0) return out;

  for (const route of routes) {
    // RULE 1: anonymous by facts we read.
    if (!route.identityReadable || route.authenticated || route.machineGated || route.tables.length === 0) continue;
    const entry = byPath.get(route.file);
    if (!entry) continue;
    const kind = route.file.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(entry.path, entry.content, ts.ScriptTarget.Latest, true, kind);

    // RULE 2: every exported handler is a readable local function.
    const handlers = handlersOf(sf);
    if (!handlers) continue;

    let gate: GateBody | null = null;
    let refused = false;
    for (const fn of handlers) {
      const result = evaluateHandler(fn, route.file, sf, models);
      if (result === null) { refused = true; break; }
      if (result !== "inert" && !gate) gate = result;
    }
    if (refused || !gate) continue;
    out.set(route.path, { path: route.path, file: route.file, ...gate });
  }
  return out;
}

// ─── Customer-facing wording ─────────────────────────────────────────────────

function joinWords(items: string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/**
 * The finding a customer reads. Deterministic: the model's title and
 * consequence were written for `missing_authentication` and would put a
 * critical's words on an informational finding.
 */
export function renderPossessionGate(gate: PossessionGate): {
  title: string;
  consequence: string;
  claims: { claim: string; origin: "routes" | "schema"; verified: boolean }[];
} {
  const matched = joinWords(gate.bindings.map((b) => b.field));
  return {
    title: `${gate.path} admits anyone holding a ${gate.model} id`,
    // States the mechanism and stops. Whether possession SHOULD be enough is the
    // customer's intent, which we did not read; saying "this is by design" would
    // be the crediting this class exists not to do.
    consequence:
      `This endpoint does not check who is calling. It checks that the caller holds a ${gate.model} id ` +
      `that matches the ${joinWords(gate.bindings.map((b) => b.field))} in the same request. ` +
      `Whether holding that id should be enough is your decision; below is what we read.`,
    claims: [
      {
        claim: `${gate.file}:${gate.lookupLine} looks up the ${gate.model} by the ${gate.param} in ${gate.paramSource} and refuses the request when none is found. No session or signature is checked.`,
        origin: "routes",
        verified: true,
      },
      {
        claim:
          `The same lookup also requires the ${gate.model} to match ${matched}: ` +
          gate.bindings.map((b) => `${b.field} against ${b.source} (${b.file}:${b.line})`).join("; ") +
          `. Those values arrive with the same request, so a ${gate.model} id is accepted only alongside the records it belongs to. That is a consistency check, not a check on who is calling.`,
        origin: "routes",
        verified: true,
      },
      {
        claim: `${gate.model}.${gate.field} is generated by the schema as ${gate.mint.expression} (${gate.mint.file}:${gate.mint.line}), which is ${gate.mint.strength}.`,
        origin: "schema",
        verified: true,
      },
      {
        claim: `Not read: whether a ${gate.model} id is ever shown to anyone other than the person holding it, in a page, a response, a log or an email. If it is, whoever sees it can use this endpoint. You can check that; we cannot.`,
        origin: "routes",
        verified: false,
      },
    ],
  };
}

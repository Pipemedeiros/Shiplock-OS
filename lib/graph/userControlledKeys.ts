import ts from "typescript";

/**
 * "A value the caller controls chooses what is destroyed" (Step 7F).
 *
 * Within one entry point (a route handler or a browser-callable server
 * action), a storage or file deletion whose key the caller controls, with no
 * check that the key is the caller's. Read from the TypeScript syntax tree.
 *
 * Sources: request input (`parsedInput`, `req.json()`, `req.nextUrl...`,
 * FormData, URL params, a helper handed the request), exported functions' own
 * parameters (server actions), editable fields of the caller's record
 * (`ctx.user.image`), and rows read by a caller-chosen value with no owner
 * filter (Prisma or Supabase).
 *
 * Every tainted value has its own root: a field of the input
 * (`parsedInput.storageKey`) or a row (`file`). A check clears only the root
 * it checks, and only in the direction it proves: after `if (!owned) exit`
 * the value is owned; inside `if (owned) { ... }` it is owned; an inverted
 * guard proves nothing. Ownership means comparing with the caller's real
 * identity (never an id the caller sent), an owner-filtered check or list
 * naming the value, an assert/owns helper given the value and the identity,
 * or an allowlist of literals. A prefix check stops counting once the value
 * is joined into a filesystem path, where `../` can escape it.
 *
 * Out of scope, never cleared: flows through other functions or files.
 */
export type UserControlledDelete = { entry: string; sink: string; source: string };

type Taint = { source: string; root: string; basename: boolean; prefixOnly: boolean; joined: boolean; row: boolean };
type Fact = { root: string; kind: "owned" | "prefix" | "notOwned" };

const REQUEST = new Set(["req", "request"]);
const INPUT_ROOTS = new Set(["parsedInput", "searchParams", "params", "formData"]);
// Caller input only when destructured from a callback parameter (tRPC `({ input, ctx })`);
// a local variable that happens to be named `input` is not.
const PARAM_INPUT_KEYS = new Set(["input"]);
const NOT_PARAMS = new Set(["req", "request", "ctx", "context", "_", "event", "prev", "prevState", "state"]);
const EDITABLE = /^(?:image|avatar\w*|picture|photo\w*|logo\w*|file\w*|key|path|url)$/;
const CALLER_OBJECTS = /^(?:ctx\.user|ctx\.session\.user|session\.user|user|currentUser)$/;
const SINK_NAMES = new Set(["deleteObject", "deleteObjects", "deleteFile", "deleteFiles", "removeFile", "removeFiles",
  "removeObject", "removeObjects", "unlink", "unlinkSync", "del"]);
const UPLOAD_RESULTS = new Set(["put", "upload", "uploadFile", "uploadFiles", "putObject", "createPresignedPost"]);
const PASS_THROUGH = new Set(["basename", "join", "resolve", "normalize", "trim", "toLowerCase", "toUpperCase", "split",
  "slice", "substring", "replace", "replaceAll", "concat", "toString", "String", "decodeURIComponent", "encodeURIComponent",
  "at", "get", "getAll", "map", "filter", "flatMap", "find", "values", "keys", "pop", "shift", "reduce"]);
// Azure Blob: a blob client's own delete, keyed by the getter's argument.
const BLOB_CLIENT_GETTERS = /^get(?:Block|Append|Page)?BlobClient$/;
// Cloudflare bindings (R2, KV) are upper-case names on `env`.
const BINDING_DELETE = /(?:^|\.)env\.[A-Z][A-Z0-9_]*\.delete$/;
const EXIT_CALLS = /^(?:notFound|forbidden|unauthorized|redirect|permanentRedirect)$/;
const ASSERTS = /^(?:assert|owns|isOwn|belongsTo|authorize|check\w*Owner|(?:require|ensure|verify)\w*Own)/i;
const IDENTITY_TEXT = /^(?:ctx\.user\.id|ctx\.session\.user\.id|session\.user\.id|session\.userId|user\.id|currentUser\.id|auth\(\)\.userId|ctx\.userId)$/;
const IDENTITY_SOURCES = /^(?:auth|getAuth|currentUser|getSession|getServerSession|getUser)\(/;

const text = (node: ts.Node) => node.getText().replace(/\s+/g, "").replace(/\?\./g, ".");
const unwrap = (e: ts.Expression): ts.Expression =>
  ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isAwaitExpression(e)
    || ts.isTypeAssertionExpression(e) || ts.isSatisfiesExpression(e) ? unwrap(e.expression) : e;

export function findUserControlledDeletes(body: string, entry: string): UserControlledDelete[] {
  const file = ts.createSourceFile("entry.tsx", body, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const taint = new Map<string, Taint>();
  const identities = new Set<string>();
  const cleared = new Map<string, "owned" | "prefix">();
  const ownerScoped = new Set<string>(); // variables holding owner-filtered results
  const ownerChecks = new Map<string, string[]>(); // variable -> roots an owner-filtered check named
  const boolFacts = new Map<string, { whenTrue: Fact[]; whenFalse: Fact[] }>(); // const booleans holding a check
  const allowSets = new Set<string>();
  const identityDerived = new Set<string>(); // untainted values built from the caller's id
  const buckets = new Set<string>();
  const out: UserControlledDelete[] = [];

  const isIdentity = (e: ts.Node): boolean => IDENTITY_TEXT.test(text(e)) || (ts.isIdentifier(e) && identities.has(e.text));
  const mentionsIdentity = (e: ts.Node): boolean => {
    let found = false;
    const visit = (n: ts.Node) => { if (found) return; if (isIdentity(n) || (ts.isIdentifier(n) && identityDerived.has(n.text))) { found = true; return; } ts.forEachChild(n, visit); };
    visit(e);
    return found;
  };
  const make = (source: string, root: string, row = false): Taint =>
    ({ source, root, basename: false, prefixOnly: false, joined: false, row });

  function calleeName(call: ts.CallExpression): string {
    const c = call.expression;
    return ts.isPropertyAccessExpression(c) ? c.name.text : ts.isIdentifier(c) ? c.text : "";
  }

  /** Every call in a method chain, outermost first (for query builders). */
  function chain(e: ts.Expression): ts.CallExpression[] {
    const calls: ts.CallExpression[] = [];
    let cur: ts.Expression = unwrap(e);
    while (true) {
      if (ts.isCallExpression(cur)) { calls.push(cur); cur = cur.expression; continue; }
      if (ts.isPropertyAccessExpression(cur)) { cur = cur.expression; continue; }
      break;
    }
    return calls;
  }

  function taintOf(e: ts.Node | undefined): Taint | null {
    if (!e) return null;
    const x = ts.isExpression(e as ts.Expression) ? unwrap(e as ts.Expression) : e;
    if (ts.isIdentifier(x)) {
      if (INPUT_ROOTS.has(x.text)) return make(x.text, x.text);
      const t = taint.get(x.text);
      if (!t) return null;
      const state = cleared.get(t.root);
      if (state === "owned") return null;
      return state === "prefix" ? { ...t, prefixOnly: true } : t;
    }
    if (ts.isPropertyAccessExpression(x) || ts.isElementAccessExpression(x)) {
      const owner = text(x.expression);
      if (ts.isPropertyAccessExpression(x) && CALLER_OBJECTS.test(owner) && EDITABLE.test(x.name.text)) return make(text(x), text(x));
      if (REQUEST.has(owner)) return make(text(x), text(x));
      const inner = taintOf(x.expression);
      if (!inner) return null;
      // A field of an input object is its own root; a field of a row shares the row's root.
      if (!inner.row && ts.isPropertyAccessExpression(x)) {
        const root = `${inner.root}.${x.name.text}`;
        const state = cleared.get(root);
        if (state === "owned") return null;
        return { ...inner, source: inner.source.includes(".") ? inner.source : text(x), root, prefixOnly: inner.prefixOnly || state === "prefix" };
      }
      return inner;
    }
    if (ts.isTemplateExpression(x)) {
      const parts = x.templateSpans.map((s) => taintOf(s.expression)).filter((t): t is Taint => t !== null);
      if (!parts.length) return null;
      if (mentionsIdentity(x) && parts.every((p) => p.basename)) return null;
      return parts[0];
    }
    if (ts.isBinaryExpression(x)) {
      const k = x.operatorToken.kind;
      if (k === ts.SyntaxKind.PlusToken || k === ts.SyntaxKind.BarBarToken || k === ts.SyntaxKind.QuestionQuestionToken) return taintOf(x.left) ?? taintOf(x.right);
      return null;
    }
    if (ts.isConditionalExpression(x)) return taintOf(x.whenTrue) ?? taintOf(x.whenFalse);
    if (ts.isSpreadElement(x)) return taintOf(x.expression);
    if (ts.isArrayLiteralExpression(x)) { for (const el of x.elements) { const t = taintOf(el); if (t) return t; } return null; }
    if (ts.isObjectLiteralExpression(x)) {
      for (const p of x.properties) {
        const t = ts.isPropertyAssignment(p) ? taintOf(p.initializer) : ts.isShorthandPropertyAssignment(p) ? taintOf(p.name)
          : ts.isSpreadAssignment(p) ? taintOf(p.expression) : null;
        if (t) return t;
      }
      return null;
    }
    if (ts.isNewExpression(x)) return text(x.expression) === "URL" ? taintOf(x.arguments?.[0]) : null;
    if (ts.isCallExpression(x)) return callTaint(x);
    return null;
  }

  function callTaint(call: ts.CallExpression): Taint | null {
    const name = calleeName(call);
    const receiver = ts.isPropertyAccessExpression(call.expression) ? call.expression.expression : null;
    const callee = text(call.expression);
    if (receiver && ts.isIdentifier(receiver) && REQUEST.has(receiver.text) && /^(?:json|formData|text)$/.test(name)) {
      return make(`${receiver.text}.${name}()`, `${receiver.text}.${name}`);
    }
    if (call.arguments.some((a) => ts.isIdentifier(a) && REQUEST.has(a.text))) return make(`${callee}(${text(call.arguments[0])})`, callee);
    if (UPLOAD_RESULTS.has(name)) return null;
    // Query builders (Prisma, Supabase): a caller-chosen value with no owner filter reads a caller-chosen row.
    const calls = chain(call);
    const isQuery = /^(?:prisma|db|tx)\.\w+\.(?:find\w*|count)$/.test(callee)
      || calls.some((c) => /\.from$/.test(text(c.expression)) && !/\.storage\.from$/.test(text(c.expression)));
    if (isQuery) {
      if (calls.some((c) => c.arguments.some((a) => mentionsIdentity(a)))) return null;
      for (const c of calls) for (const a of c.arguments) {
        const t = taintOf(a);
        if (t) return { ...make(`${callee.split("(")[0]} by ${t.source}`, `row:${t.root}`, true) };
      }
      return null;
    }
    const receiverTaint = receiver ? taintOf(receiver) : null;
    const argTaint = call.arguments.map((a) => taintOf(a)).find((t) => t !== null) ?? null;
    if (PASS_THROUGH.has(name)) {
      const t = receiverTaint ?? argTaint;
      if (!t) return null;
      // A path joined under the caller's own directory is theirs only if `../` was stripped.
      if (call.arguments.some((a) => mentionsIdentity(a)) && (name !== "join" && name !== "resolve" || t.basename)) return null;
      if ((name === "get" || name === "getAll") && !t.source.includes(".")) return { ...t, source: `${t.source}.get` };
      return { ...t, basename: name === "basename" ? true : t.basename, joined: t.joined || name === "join" || name === "resolve" };
    }
    if (call.arguments.some((a) => mentionsIdentity(a))) return null;
    if (callee === "JSON.parse") return argTaint;
    return null;
  }

  function bind(name: ts.BindingName, t: Taint | null, init?: ts.Expression) {
    if (ts.isIdentifier(name)) {
      if (!t) { taint.delete(name.text); return; }
      // A row gets its own root, so a check on this row clears only this row.
      taint.set(name.text, t.row || t.joined ? { ...t, root: name.text } : t);
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const el of name.elements) {
        if (!ts.isBindingElement(el)) continue;
        const key = el.propertyName ? el.propertyName.getText() : ts.isIdentifier(el.name) ? el.name.text : null;
        const fieldTaint = t && !t.row && key && !el.dotDotDotToken ? { ...t, root: `${t.root}.${key}`, source: t.source.includes(".") ? t.source : `${t.source}.${key}` } : t;
        if (ts.isIdentifier(el.name) && init && isIdentitySource(init) && /^(?:userId|id)$/.test(key ?? "")) identities.add(el.name.text);
        bind(el.name, fieldTaint);
      }
      return;
    }
    if (ts.isArrayBindingPattern(name)) for (const el of name.elements) if (ts.isBindingElement(el)) bind(el.name, t);
  }

  const isIdentitySource = (e: ts.Expression) => IDENTITY_SOURCES.test(text(unwrap(e)));

  /** Facts that hold when `cond` is true (polarity true) or false (false). */
  function facts(cond: ts.Expression, whenTrue: boolean): Fact[] {
    const c = unwrap(cond);
    if (ts.isPrefixUnaryExpression(c) && c.operator === ts.SyntaxKind.ExclamationToken) return facts(c.operand, !whenTrue);
    if (ts.isBinaryExpression(c)) {
      const k = c.operatorToken.kind;
      if (k === ts.SyntaxKind.AmpersandAmpersandToken) return whenTrue ? [...facts(c.left, true), ...facts(c.right, true)] : [];
      if (k === ts.SyntaxKind.BarBarToken) return whenTrue ? [] : [...facts(c.left, false), ...facts(c.right, false)];
      const eq = k === ts.SyntaxKind.EqualsEqualsEqualsToken || k === ts.SyntaxKind.EqualsEqualsToken;
      const ne = k === ts.SyntaxKind.ExclamationEqualsEqualsToken || k === ts.SyntaxKind.ExclamationEqualsToken;
      if (eq || ne) {
        const trusted = (e: ts.Expression) => isIdentity(e) || (mentionsIdentity(e) && !taintOf(e));
        const side = trusted(c.right) ? taintOf(c.left) : trusted(c.left) ? taintOf(c.right) : null;
        if (!side) return [];
        const owned = eq === whenTrue;
        return [{ root: side.root, kind: owned ? "owned" : "notOwned" }];
      }
      return [];
    }
    if (ts.isCallExpression(c)) {
      const name = calleeName(c);
      const receiver = ts.isPropertyAccessExpression(c.expression) ? unwrap(c.expression.expression) : null;
      let root: string | null = null, kind: "owned" | "prefix" = "owned";
      if ((name === "startsWith" || name === "includes") && receiver && c.arguments.some((a) => mentionsIdentity(a))) {
        const checked = taintOf(receiver);
        root = checked?.root ?? null; kind = name === "startsWith" && !checked?.joined ? "prefix" : "owned";
      } else if ((name === "includes" || name === "has") && receiver) {
        const isAllow = (ts.isArrayLiteralExpression(receiver) && receiver.elements.every((el) => ts.isStringLiteral(el)))
          || (ts.isIdentifier(receiver) && (allowSets.has(receiver.text) || ownerScoped.has(receiver.text)));
        if (isAllow) root = taintOf(c.arguments[0])?.root ?? null;
      } else if (ASSERTS.test(name) && c.arguments.some((a) => mentionsIdentity(a))) {
        // The checked value may be wrapped (`requireOwnership(await getFile(key), uid)`).
        const deepRoot = (n: ts.Node): string | null => {
          const t = ts.isExpression(n as ts.Expression) && !isIdentity(n) ? taintOf(n) : null;
          if (t) return t.root;
          let found: string | null = null;
          ts.forEachChild(n, (child) => { found ??= deepRoot(child); });
          return found;
        };
        for (const a of c.arguments) { root = deepRoot(a); if (root) break; }
      }
      if (!root) return [];
      return whenTrue ? [{ root, kind }] : [{ root, kind: "notOwned" }];
    }
    if (ts.isIdentifier(c) && boolFacts.has(c.text)) {
      const held = boolFacts.get(c.text)!;
      return whenTrue ? held.whenTrue : held.whenFalse;
    }
    if (ts.isIdentifier(c) && ownerChecks.has(c.text)) {
      return ownerChecks.get(c.text)!.map((root) => ({ root, kind: whenTrue ? "owned" as const : "notOwned" as const }));
    }
    return [];
  }

  const exits = (s: ts.Statement): boolean => {
    if (ts.isThrowStatement(s) || ts.isReturnStatement(s)) return true;
    if (ts.isExpressionStatement(s)) { const e = unwrap(s.expression); return ts.isCallExpression(e) && EXIT_CALLS.test(calleeName(e)); }
    if (ts.isBlock(s)) return s.statements.some(exits);
    return false;
  };

  function applyFacts(fs: Fact[]) {
    for (const f of fs) if (f.kind !== "notOwned" && cleared.get(f.root) !== "owned") cleared.set(f.root, f.kind);
  }

  function checkSink(node: ts.CallExpression | ts.NewExpression) {
    let sink: string | null = null;
    let args: readonly ts.Expression[] = node.arguments ?? [];
    const callee = text(node.expression);
    if (ts.isNewExpression(node)) {
      if (/^Delete(?:Object|Objects)Command$/.test(callee)) sink = callee;
    } else {
      const name = calleeName(node);
      const receiver = ts.isPropertyAccessExpression(node.expression) ? unwrap(node.expression.expression) : null;
      if (name === "remove" && receiver && (/\.storage\.from\(/.test(text(receiver)) || (ts.isIdentifier(receiver) && buckets.has(receiver.text)))) sink = "storage.from().remove";
      else if (name === "delete" && receiver && ts.isCallExpression(receiver) && calleeName(receiver) === "file") { sink = "file().delete"; args = receiver.arguments; }
      else if ((name === "delete" || name === "deleteIfExists") && receiver && ts.isCallExpression(receiver) && BLOB_CLIENT_GETTERS.test(calleeName(receiver))) {
        sink = `${calleeName(receiver)}().${name}`; args = receiver.arguments;
      }
      else if (name === "deleteBlob") sink = "deleteBlob";
      else if (BINDING_DELETE.test(callee)) sink = callee.split(".").slice(-3).join(".");
      else if (/(?:^|\.)(?:storage|bucket)\.delete$/.test(callee)) sink = callee.split(".").slice(-2).join(".");
      else if (/^(?:fs|fsp|fs\.promises)\.(?:unlink|unlinkSync|rm|rmSync)$/.test(callee)) sink = callee;
      else if (SINK_NAMES.has(name) && (ts.isIdentifier(node.expression) || /^(?:utapi|s3|storage|client|blob)\./.test(callee))) sink = name;
    }
    if (!sink) return;
    for (const arg of args) {
      const t = taintOf(arg);
      if (t && (!t.prefixOnly || t.joined)) { out.push({ entry, sink, source: t.source }); return; }
    }
  }

  function walk(node: ts.Node) {
    if (ts.isVariableDeclaration(node)) {
      const init = node.initializer;
      if (init) walk(init);
      if (init && ts.isIdentifier(node.name)) {
        const u = unwrap(init);
        // Only a const can stand in for its check; a let may be reassigned before the guard.
        if (ts.isVariableDeclarationList(node.parent) && (node.parent.flags & ts.NodeFlags.Const)) {
          const whenTrue = facts(init, true), whenFalse = facts(init, false);
          if (whenTrue.length || whenFalse.length) boolFacts.set(node.name.text, { whenTrue, whenFalse });
        }
        if (isIdentity(u)) identities.add(node.name.text);
        else if (mentionsIdentity(u) && !taintOf(u)) identityDerived.add(node.name.text);
        if (ts.isNewExpression(u) && text(u.expression) === "Set" && u.arguments?.[0] && ts.isArrayLiteralExpression(u.arguments[0])
          && u.arguments[0].elements.every((el) => ts.isStringLiteral(el))) allowSets.add(node.name.text);
        if (/\.storage\.from\(/.test(text(u)) && !/\.remove\(/.test(text(u))) buckets.add(node.name.text);
        const queries = [u, ...chain(u)].filter(ts.isCallExpression);
        const ownerFiltered = mentionsIdentity(init) && /\b(?:prisma|db|tx)\.\w+\.|\.from\(/.test(init.getText());
        if (ownerFiltered) {
          ownerScoped.add(node.name.text);
          const roots: string[] = [];
          for (const q of queries) for (const a of q.arguments) {
            const visit = (n: ts.Node) => { const t = ts.isExpression(n as ts.Expression) && !isIdentity(n) ? taintOf(n) : null; if (t) roots.push(t.root); else ts.forEachChild(n, visit); };
            visit(a);
          }
          if (roots.length) ownerChecks.set(node.name.text, roots);
        }
      }
      bind(node.name, init ? taintOf(init) : null, init);
      return;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      walk(node.right);
      bind(node.left, taintOf(node.right));
      return;
    }
    if (ts.isForOfStatement(node)) {
      const t = taintOf(node.expression);
      if (ts.isVariableDeclarationList(node.initializer)) for (const d of node.initializer.declarations) bind(d.name, t);
      walk(node.statement);
      return;
    }
    if (ts.isTryStatement(node)) {
      const saved = new Map(cleared);
      walk(node.tryBlock);
      if (node.catchClause && !exits(node.catchClause.block)) { cleared.clear(); for (const [k, v] of saved) cleared.set(k, v); }
      if (node.catchClause) walk(node.catchClause.block);
      if (node.finallyBlock) walk(node.finallyBlock);
      return;
    }
    if (ts.isIfStatement(node)) {
      walk(node.expression);
      const saved = new Map(cleared);
      applyFacts(facts(node.expression, true));
      walk(node.thenStatement);
      cleared.clear(); for (const [k, v] of saved) cleared.set(k, v);
      if (node.elseStatement) { applyFacts(facts(node.expression, false)); walk(node.elseStatement); cleared.clear(); for (const [k, v] of saved) cleared.set(k, v); }
      // After the if: what the exiting branch rules out now holds.
      if (exits(node.thenStatement)) applyFacts(facts(node.expression, false));
      else if (node.elseStatement && exits(node.elseStatement)) applyFacts(facts(node.expression, true));
      return;
    }
    if (ts.isExpressionStatement(node)) {
      const e = unwrap(node.expression);
      if (ts.isCallExpression(e) && ASSERTS.test(calleeName(e))) { walk(e); applyFacts(facts(e, true)); return; }
    }
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
      if (receiver && /^(?:map|forEach|flatMap|filter|some|every)$/.test(name)) {
        const t = taintOf(receiver);
        const fn = node.arguments[0];
        if (t && fn && (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && fn.parameters[0]) bind(fn.parameters[0].name, t);
      }
      ts.forEachChild(node, walk);
      checkSink(node);
      return;
    }
    if (ts.isNewExpression(node)) { ts.forEachChild(node, walk); checkSink(node); return; }
    if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node))) {
      for (const p of node.parameters) {
        if (!ts.isObjectBindingPattern(p.name)) continue;
        for (const el of p.name.elements) {
          const key = el.propertyName ? el.propertyName.getText() : ts.isIdentifier(el.name) ? el.name.text : "";
          if (INPUT_ROOTS.has(key) && !(ts.isIdentifier(el.name) && el.name.text === key)) bind(el.name, make(key, key));
          else if (PARAM_INPUT_KEYS.has(key)) bind(el.name, make(key, key));
        }
      }
    }
    if (ts.isFunctionDeclaration(node) && ts.isSourceFile(node.parent)) {
      // Only exported functions are callable entries (server actions); a
      // private helper's parameters are whatever its callers pass.
      const exported = ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
      for (const p of node.parameters) {
        if (!ts.isIdentifier(p.name)) continue;
        if (exported && !NOT_PARAMS.has(p.name.text)) taint.set(p.name.text, make(p.name.text, p.name.text));
        else taint.delete(p.name.text);
      }
    }
    ts.forEachChild(node, walk);
  }

  walk(file);
  return out;
}

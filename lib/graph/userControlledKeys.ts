import ts from "typescript";

/**
 * "A value the caller controls chooses what is destroyed" (Step 7F).
 *
 * Within one entry point (a route handler or a browser-callable server
 * action), a storage or file deletion whose key the caller controls, with no
 * check that the key is the caller's. Read from the TypeScript syntax tree:
 *
 * Sources: request input (`parsedInput`, `req.json()`, `formData`, URL
 * params, a helper handed the request), a server action's own parameters,
 * editable fields of the caller's record (`ctx.user.image`), and rows read by
 * a caller-chosen id with no owner filter.
 * Flow: declarations and later assignments, destructuring (rest included),
 * `for...of`, callbacks of `.map/.forEach/...`, templates and string helpers.
 * Cleared: a guard comparing a value derived from the key with the caller's
 * real identity (never with an id the caller sent), an owner-filtered
 * database check naming the key, an assert/owns-style helper given both the
 * key and the caller's identity, an allowlist check, or a key that embeds the
 * caller's identity with every caller part reduced to a basename.
 * Sinks: S3 Delete(s)ObjectCommand, fs unlink/rm, Supabase
 * `storage.from(b).remove`, UploadThing `deleteFiles`, `del`, deleteObject(s),
 * deleteFile(s), removeFile(s)/removeObject(s), `storage/bucket.delete`.
 *
 * Out of scope, never cleared: flows through other functions or files.
 */
export type UserControlledDelete = { entry: string; sink: string; source: string };

type Taint = { source: string; root: string; basename: boolean };

const INPUT_ROOTS = new Set(["parsedInput", "searchParams", "params", "formData"]);
const REQUEST = new Set(["req", "request"]);
const NOT_PARAMS = new Set(["req", "request", "ctx", "context", "_", "event"]);
const EDITABLE = /^(?:image|avatar\w*|picture|photo\w*|logo\w*|file\w*|key|path|url)$/;
const CALLER_OBJECTS = /^(?:ctx\.user|session\.user|user|currentUser)$/;
const SINK_NAMES = new Set(["deleteObject", "deleteObjects", "deleteFile", "deleteFiles", "removeFile", "removeFiles",
  "removeObject", "removeObjects", "unlink", "del"]);
const UPLOAD_RESULTS = new Set(["put", "upload", "uploadFile", "uploadFiles", "putObject", "createPresignedPost"]);
const PASS_THROUGH = new Set(["basename", "join", "resolve", "normalize", "trim", "toLowerCase", "toUpperCase", "split",
  "slice", "substring", "replace", "replaceAll", "concat", "toString", "String", "decodeURIComponent", "encodeURIComponent", "at"]);

const text = (node: ts.Node) => node.getText();

export function findUserControlledDeletes(body: string, entry: string): UserControlledDelete[] {
  const file = ts.createSourceFile("entry.tsx", body, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const taint = new Map<string, Taint>();
  const identities = new Set<string>();
  const sanitized = new Set<string>();
  const out: UserControlledDelete[] = [];

  const isIdentity = (e: ts.Node): boolean => {
    const t = text(e).replace(/\s+/g, "");
    return /^(?:ctx\.user\.id|session\.user\.id|session\.userId|user\.id|currentUser\.id|auth\(\)\.userId|ctx\.userId)$/.test(t)
      || (ts.isIdentifier(e) && identities.has(e.text));
  };
  const mentionsIdentity = (e: ts.Node): boolean => {
    let found = false;
    const visit = (n: ts.Node) => { if (found) return; if (isIdentity(n)) { found = true; return; } ts.forEachChild(n, visit); };
    visit(e);
    return found;
  };

  /** The taint of an expression, or null. */
  function taintOf(e: ts.Node | undefined): Taint | null {
    if (!e) return null;
    if (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isAwaitExpression(e)
      || ts.isTypeAssertionExpression(e) || ts.isSatisfiesExpression(e)) return taintOf(e.expression);
    if (ts.isIdentifier(e)) {
      if (INPUT_ROOTS.has(e.text)) return { source: e.text, root: e.text, basename: false };
      const t = taint.get(e.text);
      return t && !sanitized.has(t.root) ? t : null;
    }
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const owner = text(e.expression).replace(/\s+/g, "");
      if (ts.isPropertyAccessExpression(e) && CALLER_OBJECTS.test(owner) && EDITABLE.test(e.name.text)) {
        return { source: text(e), root: text(e), basename: false };
      }
      const inner = taintOf(e.expression);
      if (!inner) return null;
      return ts.isIdentifier(e.expression) && INPUT_ROOTS.has(e.expression.text)
        ? { source: text(e), root: text(e.expression), basename: false } : inner;
    }
    if (ts.isTemplateExpression(e)) {
      const parts = e.templateSpans.map((s) => taintOf(s.expression)).filter((t): t is Taint => t !== null);
      if (!parts.length) return null;
      // The caller's own folder, with every caller part reduced to a basename: safe.
      if (mentionsIdentity(e) && parts.every((p) => p.basename)) return null;
      return parts[0];
    }
    if (ts.isBinaryExpression(e)) {
      if (e.operatorToken.kind === ts.SyntaxKind.PlusToken) return taintOf(e.left) ?? taintOf(e.right);
      if ([ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(e.operatorToken.kind)) return taintOf(e.left) ?? taintOf(e.right);
      return null;
    }
    if (ts.isConditionalExpression(e)) return taintOf(e.whenTrue) ?? taintOf(e.whenFalse);
    if (ts.isArrayLiteralExpression(e)) { for (const el of e.elements) { const t = taintOf(el); if (t) return t; } return null; }
    if (ts.isObjectLiteralExpression(e)) {
      for (const p of e.properties) {
        const t = ts.isPropertyAssignment(p) ? taintOf(p.initializer) : ts.isShorthandPropertyAssignment(p) ? taintOf(p.name) : null;
        if (t) return t;
      }
      return null;
    }
    if (ts.isCallExpression(e)) return callTaint(e);
    return null;
  }

  function calleeName(call: ts.CallExpression): string {
    const c = call.expression;
    return ts.isPropertyAccessExpression(c) ? c.name.text : ts.isIdentifier(c) ? c.text : "";
  }

  function callTaint(call: ts.CallExpression): Taint | null {
    const name = calleeName(call);
    const receiver = ts.isPropertyAccessExpression(call.expression) ? call.expression.expression : null;
    const callee = text(call.expression).replace(/\s+/g, "");
    // Request bodies and helpers handed the request.
    if (receiver && ts.isIdentifier(receiver) && REQUEST.has(receiver.text) && /^(?:json|formData|text)$/.test(name)) {
      return { source: `${receiver.text}.json()`.replace("json()", `${name}()`), root: `${receiver.text}.${name}`, basename: false };
    }
    if (call.arguments.some((a) => ts.isIdentifier(a) && REQUEST.has(a.text))) return { source: `${callee}(${text(call.arguments[0])})`, root: callee, basename: false };
    if (receiver && text(receiver) === "formData" && name === "get") return { source: "formData.get", root: "formData", basename: false };
    if (receiver && /^(?:searchParams|params)$/.test(text(receiver)) && name === "get") return { source: `${text(receiver)}.get`, root: text(receiver), basename: false };
    // Server-issued results: uploads, and anything scoped by the caller's identity.
    if (UPLOAD_RESULTS.has(name)) return null;
    if (call.arguments.some((a) => mentionsIdentity(a))) return null;
    // Database reads: a caller-chosen where with no owner filter is a caller-chosen row.
    if (/^(?:prisma|db|tx)\.\w+\.find\w*$/.test(callee)) {
      const arg = call.arguments[0];
      const where = arg && ts.isObjectLiteralExpression(arg) ? arg.properties.find((p) => p.name && text(p.name) === "where") : undefined;
      const t = where && ts.isPropertyAssignment(where) ? taintOf(where.initializer) : null;
      return t ? { source: `${callee} by ${t.source}`, root: t.root, basename: false } : null;
    }
    if (/^(?:prisma|db|tx|supabase\w*)\b/.test(callee) || /\.from$/.test(callee) || /\.(?:select|single|maybeSingle|lt|eq|limit)$/.test(callee)) return null;
    // Pass-through helpers keep the taint; a basename is recorded.
    const receiverTaint = receiver ? taintOf(receiver) : null;
    const argTaint = call.arguments.map((a) => taintOf(a)).find((t) => t !== null) ?? null;
    if (PASS_THROUGH.has(name) || name === "map" || name === "filter") {
      const t = receiverTaint ?? argTaint;
      return t ? { ...t, basename: name === "basename" ? true : t.basename } : null;
    }
    if (name === "parse" && text(call.expression) === "JSON.parse") return argTaint;
    return null;
  }

  /** Bind a pattern (identifier or destructuring) to a taint. */
  function bind(name: ts.BindingName | ts.Expression, t: Taint | null) {
    if (ts.isIdentifier(name)) { if (t) taint.set(name.text, t); else taint.delete(name.text); return; }
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const el of name.elements) if (ts.isBindingElement(el)) bind(el.name, t);
    }
  }

  function noteIdentity(name: ts.BindingName, init: ts.Expression | undefined) {
    if (ts.isIdentifier(name) && init && isIdentity(init)) identities.add(name.text);
  }

  /** Roots a guard condition proves the caller owns (or allowlists). */
  function guardClears(cond: ts.Expression): string[] {
    const roots: string[] = [];
    const visit = (n: ts.Node) => {
      if (ts.isBinaryExpression(n) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken,
        ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(n.operatorToken.kind)) {
        const l = taintOf(n.left), r = taintOf(n.right);
        if (l && isIdentity(n.right)) roots.push(l.root);
        if (r && isIdentity(n.left)) roots.push(r.root);
      }
      if (ts.isCallExpression(n)) {
        const name = calleeName(n);
        const receiver = ts.isPropertyAccessExpression(n.expression) ? n.expression.expression : null;
        if ((name === "startsWith" || name === "includes") && receiver) {
          const t = taintOf(receiver);
          if (t && n.arguments.some((a) => mentionsIdentity(a))) roots.push(t.root);
          // Allowlist: [..literals].includes(value)
          if (name === "includes" && ts.isArrayLiteralExpression(receiver) && receiver.elements.every((el) => ts.isStringLiteral(el))) {
            const v = taintOf(n.arguments[0]);
            if (v) roots.push(v.root);
          }
        }
        if (/^(?:assert|owns|isOwn|belongsTo|authorize|check\w*Owner)/i.test(name)) {
          const v = n.arguments.map((a) => taintOf(a)).find((t) => t);
          if (v && n.arguments.some((a) => mentionsIdentity(a))) roots.push(v.root);
        }
      }
      if (ts.isIdentifier(n) && ownerChecked.has(n.text)) roots.push(...ownerChecked.get(n.text)!);
      ts.forEachChild(n, visit);
    };
    visit(cond);
    return roots;
  }

  // Variables holding an owner-filtered check that names a tainted value.
  const ownerChecked = new Map<string, string[]>();
  const ownerFilteredCheck = (e: ts.Expression | undefined): string[] => {
    let inner = e;
    while (inner && (ts.isAwaitExpression(inner) || ts.isParenthesizedExpression(inner))) inner = inner.expression;
    if (!inner || !ts.isCallExpression(inner) || !/^(?:prisma|db|tx)\.\w+\.(?:count|find\w*)$/.test(text(inner.expression).replace(/\s+/g, ""))) return [];
    const arg = inner.arguments[0];
    if (!arg || !mentionsIdentity(arg)) return [];
    const roots: string[] = [];
    const visit = (n: ts.Node) => { const t = ts.isIdentifier(n) || ts.isPropertyAccessExpression(n) ? taintOf(n as ts.Expression) : null; if (t) roots.push(t.root); ts.forEachChild(n, visit); };
    visit(arg);
    return roots;
  };

  function checkSink(call: ts.CallExpression | ts.NewExpression) {
    const name = ts.isNewExpression(call) ? text(call.expression) : calleeName(call);
    const callee = text(call.expression).replace(/\s+/g, "");
    let sink: string | null = null;
    if (ts.isNewExpression(call) && /^Delete(?:Object|Objects)Command$/.test(name)) sink = name;
    else if (ts.isCallExpression(call)) {
      if (name === "remove" && /\.storage\.from\(.*\)$/.test(text(call.expression).replace(/\.remove$/, "").replace(/\s+/g, "")) ) sink = "storage.from().remove";
      else if (/(?:^|\.)(?:storage|bucket)\.delete$/.test(callee)) sink = callee.split(".").slice(-2).join(".");
      else if (/^(?:fs|fsp|fs\.promises)\.(?:unlink|rm)$/.test(callee)) sink = callee;
      else if (SINK_NAMES.has(name) && (ts.isIdentifier(call.expression) || /^(?:utapi|s3|storage|client|blob)\./.test(callee))) sink = name;
    }
    if (!sink) return;
    for (const arg of call.arguments ?? []) {
      const t = taintOf(arg);
      if (t) { out.push({ entry, sink, source: t.source }); return; }
    }
  }

  function walk(node: ts.Node) {
    if (ts.isVariableDeclaration(node)) {
      if (node.initializer) walk(node.initializer);
      noteIdentity(node.name, node.initializer);
      const checked = ownerFilteredCheck(node.initializer);
      if (checked.length && ts.isIdentifier(node.name)) ownerChecked.set(node.name.text, checked);
      bind(node.name, taintOf(node.initializer));
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
    if (ts.isIfStatement(node)) {
      walk(node.expression);
      const exits = (s: ts.Statement): boolean => ts.isThrowStatement(s) || ts.isReturnStatement(s)
        || (ts.isBlock(s) && s.statements.some((x) => ts.isThrowStatement(x) || ts.isReturnStatement(x)));
      walk(node.thenStatement);
      if (node.elseStatement) walk(node.elseStatement);
      if (exits(node.thenStatement)) for (const root of guardClears(node.expression)) sanitized.add(root);
      return;
    }
    if (ts.isExpressionStatement(node) && ts.isCallExpression(node.expression) && /^(?:assert|owns|isOwn|belongsTo|authorize|check\w*Owner)/i.test(calleeName(node.expression))) {
      for (const root of guardClears(node.expression)) sanitized.add(root);
    }
    if (ts.isCallExpression(node)) {
      // Callback parameters of .map/.forEach/... over a tainted collection.
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
    if ((ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.parent === file
      || (ts.isFunctionDeclaration(node) && ts.isSourceFile(node.parent))) {
      // A server action's own parameters are caller input.
      for (const p of node.parameters) {
        if (ts.isIdentifier(p.name) && !NOT_PARAMS.has(p.name.text)) taint.set(p.name.text, { source: p.name.text, root: p.name.text, basename: false });
      }
    }
    ts.forEachChild(node, walk);
  }

  walk(file);
  return out;
}

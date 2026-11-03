import ts from "typescript";
import { resolveImport } from "@/lib/deep/clientExposure";

/**
 * A gate one call away (found by scanning ShipLock itself).
 *
 * A route whose secret check or token check lives in a helper read as
 * "unreadable": the conservative rule (routeInventory.ts) refuses to credit a
 * helper that merely MENTIONS a secret, because mentioning is not gating.
 * This recognises the narrow shape where the helper IS the gate:
 *
 *  1. the route calls a function it imports, and rejects on its answer:
 *     `if (!F(req)) return …401|403…`, or `const x = await F(req)` followed by
 *     `if (!x) return …401|403…` or `if ("error" in x) return x.error`;
 *  2. that function's own body (or a function it calls, one import away)
 *     compares a secret or signature (machine), or resolves a HASHED token
 *     from the request's Authorization header (a signed-in caller).
 *
 * Anything else credits nothing. Crediting a gate can only make ShipLock miss
 * a finding, never invent one, so every clause is required, and an unhashed
 * token lookup (possession, not identity) is never a signed-in caller.
 */

const MACHINE_RE =
  /\b(CRON_SECRET|WEBHOOK_SECRET|constructEvent|timingSafeEqual|createHmac|verifyHmac|verifySignature|x-hub-signature|stripe-signature)\b|\.eq\s*\(\s*["']\w*token["']|\bverify[A-Za-z]*(?:Signature|Webhook)[A-Za-z]*\s*\(|(?:!==|===|!=|==)\s*process\.env\.[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|KEY)\b/i;
const HASHED_LOOKUP_RE = /\.eq\s*\(\s*["']\w*(?:token|key|secret)_?hash(?:ed)?["']\s*,/i;
const AUTH_HEADER_RE = /\.headers\s*\.get\s*\(\s*["']authorization["']|\.headers\s*\.authorization\b/i;
const REJECT_RE = /\b(?:status\s*:\s*|\b)40[13]\b/;

export type HelperGuard = { kind: "machine" | "user"; path: string };
type Files = ReadonlyMap<string, { path: string; content: string }>;

/** Named imports of a file, local name to resolved repository path. */
export function importsOf(file: string, content: string, byPath: Files): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of content.matchAll(/import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']/g)) {
    if (/^import\s*type\b/.test(m[0])) continue;
    const target = resolveImport(file, m[2], byPath as Map<string, { path: string; content: string }>);
    if (!target) continue;
    for (const part of m[1].split(",")) {
      const [name, alias] = part.replace(/^\s*type\s+/, "").split(/\s+as\s+/).map((s) => s.trim());
      if (name && /^\w+$/.test(alias ?? name)) out.set(alias ?? name, target);
    }
  }
  return out;
}

/** The body of a function declared in `content` under `name`, or null.
 * Parsed, so a return type such as `Promise<{ id: string }>` is never
 * mistaken for the body. */
export function functionBody(content: string, name: string): string | null {
  const sf = ts.createSourceFile("helper.ts", content, ts.ScriptTarget.Latest, true);
  let body: ts.Node | undefined;
  const visit = (n: ts.Node) => {
    if (body) return;
    if (ts.isFunctionDeclaration(n) && n.name?.text === name) body = n.body;
    else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer
      && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) body = n.initializer.body;
    else ts.forEachChild(n, visit);
  };
  visit(sf);
  return body ? body.getText(sf) : null;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/** The exported HTTP handlers' bodies, or null when one is not a plain body. */
function handlerBodies(sf: ts.SourceFile): ts.Block[] | null {
  const bodies: ts.Block[] = [];
  for (const st of sf.statements) {
    const exported = (n: ts.Node) => ts.canHaveModifiers(n) && (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (ts.isFunctionDeclaration(st) && st.name && METHODS.has(st.name.text) && exported(st)) {
      if (!st.body) return null;
      bodies.push(st.body);
    } else if (ts.isVariableStatement(st) && exported(st)) {
      for (const d of st.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !METHODS.has(d.name.text)) continue;
        // `export const GET = withError("x", async (request) => { … })`: the
        // handler is the wrapper call's last argument.
        let init = d.initializer;
        if (init && ts.isCallExpression(init)) init = init.arguments[init.arguments.length - 1];
        if (!init || !(ts.isArrowFunction(init) || ts.isFunctionExpression(init)) || !ts.isBlock(init.body)) return null;
        bodies.push(init.body);
      }
    }
  }
  return bodies;
}

/** What a rejecting branch returns: a 401/403 response, or the helper's own answer. */
function rejection(branch: ts.Statement, sf: ts.SourceFile): "rejects" | "own" | null {
  // Logging may come first (`log.error(…); return …401…`); anything that
  // awaits or reads data before the return does not reject.
  let first: ts.Statement | undefined = branch;
  if (ts.isBlock(branch)) {
    first = branch.statements.find((st) => !ts.isExpressionStatement(st));
    const before = branch.statements.slice(0, first ? branch.statements.indexOf(first) : 0);
    if (before.some((st) => /\bawait\b|\.from\s*\(/.test(st.getText(sf)))) return null;
  }
  if (!first || !ts.isReturnStatement(first) || !first.expression) return null;
  const text = first.expression.getText(sf);
  if (REJECT_RE.test(text)) return "rejects";
  return /^\w+\s*\.\s*(?:error|response)$/.test(text) ? "own" : null;
}

/** The imported function this handler body is gated by, if the body opens
 * with the guard: nothing before it awaits or reads data, and the guard is a
 * top-level statement (not one branch of another condition). */
function guardIn(body: ts.Block, sf: ts.SourceFile, imported: ReadonlySet<string>): { name: string; own: boolean } | null {
  const calleeOf = (e: ts.Expression): string | null => {
    let x = e;
    while (ts.isParenthesizedExpression(x) || ts.isAwaitExpression(x)) x = x.expression;
    return ts.isCallExpression(x) && ts.isIdentifier(x.expression) && imported.has(x.expression.text) ? x.expression.text : null;
  };
  const statements = body.statements;
  for (let i = 0; i < statements.length; i++) {
    const st = statements[i];
    // Shape A: if (!F(req)) return …401…
    if (ts.isIfStatement(st) && ts.isPrefixUnaryExpression(st.expression) && st.expression.operator === ts.SyntaxKind.ExclamationToken) {
      const name = calleeOf(st.expression.operand);
      const r = name ? rejection(st.thenStatement, sf) : null;
      if (name && r === "rejects") return { name, own: false };
    }
    // Shape B: const x = await F(req); if (!x | "error" in x | x.error | !x.ok) return …
    if (ts.isVariableStatement(st) && st.declarationList.declarations.length === 1) {
      const d = st.declarationList.declarations[0];
      const name = d.initializer && ts.isIdentifier(d.name) ? calleeOf(d.initializer) : null;
      const next = statements[i + 1];
      if (name && next && ts.isIfStatement(next) && ts.isIdentifier(d.name)) {
        const v = esc(d.name.text);
        const cond = next.expression.getText(sf).replace(/\s+/g, " ");
        if (new RegExp(`^(?:!\\s*${v}|["']error["'] in ${v}|${v}\\s*\\.\\s*error|!\\s*${v}\\s*\\.\\s*ok)$`).test(cond)) {
          const r = rejection(next.thenStatement, sf);
          if (r) return { name, own: r === "own" };
        }
      }
    }
    // Anything that does work before the guard ends the search: the route
    // acted before checking who called.
    const text = st.getText(sf);
    if (/\bawait\b|\.from\s*\(/.test(text)) return null;
  }
  return null;
}

/**
 * Whether `entry` (the route file's text) is gated by an imported helper, and
 * by which kind. Every exported HTTP handler must open with the same guard.
 */
export function helperGuard(file: string, entry: string, byPath: Files): HelperGuard | null {
  const imports = importsOf(file, entry, byPath);
  if (imports.size === 0) return null;
  const sf = ts.createSourceFile(file, entry, ts.ScriptTarget.Latest, true);
  const bodies = handlerBodies(sf);
  if (!bodies || bodies.length === 0) return null;
  const guards = bodies.map((b) => guardIn(b, sf, new Set(imports.keys())));
  if (guards.some((g) => !g)) return null;
  // Each handler may reject on its own helper; every one must be the same kind.
  let found: HelperGuard | null = null;
  for (const name of new Set(guards.map((g) => g!.name))) {
    const kind = classify(name, imports.get(name)!, guards.some((g) => g!.name === name && g!.own), byPath);
    if (!kind || (found && found.kind !== kind)) return null;
    found ??= { kind, path: imports.get(name)! };
  }
  return found;
}

const BARE_SECRET_NAME_RE = /\b(?:CRON_SECRET|WEBHOOK_SECRET)\b/gi;

/** What gate the helper `name` in `path` is, if it is one. */
function classify(name: string, path: string, own: boolean, byPath: Files): HelperGuard["kind"] | null {
  const helper = byPath.get(path);
  const body = helper ? functionBody(helper.content, name) : null;
  if (!helper || body === null) return null;
  // The helper's answer is returned as the response, so the rejection is the
  // helper's own: it must answer 401 or 403 itself.
  if (own && !REJECT_RE.test(body)) return null;
  // One call away from the helper: functions it imports, and functions
  // declared beside it in its own file.
  const imported = importsOf(path, helper.content, byPath);
  const callees: string[] = [];
  for (const callee of new Set([...body.matchAll(/\b(\w+)\s*\(/g)].map((m) => m[1]))) {
    if (callee === name) continue;
    const source = imported.has(callee) ? byPath.get(imported.get(callee)!)?.content ?? "" : helper.content;
    if (!imported.has(callee) && !new RegExp(`\\bfunction\\s+${callee}\\b|\\b(?:const|let)\\s+${callee}\\s*=`).test(source)) continue;
    const calleeBody = functionBody(source, callee);
    if (calleeBody) callees.push(calleeBody);
  }
  const reached = [body, ...callees].join("\n");
  if (AUTH_HEADER_RE.test(body) && HASHED_LOOKUP_RE.test(reached)) return "user";
  if (MACHINE_RE.test(body)) return "machine";
  // A callee's comparison is the gate only when the helper was handed the
  // request itself (corpus-w's verifyPat(pat) signs a cache entry beside a
  // GitHub token check), and only for a comparison, not a secret's name.
  const params = new RegExp(`(?:function\\s+${name}|\\b${name}\\s*=\\s*(?:async\\s*)?(?:function\\s*)?)\\s*\\(([^)]*)\\)`).exec(helper.content)?.[1] ?? "";
  const takesRequest = /^\s*(?:_?req|request)\b|^[^,]*:\s*(?:Next)?Request\b/.test(params);
  if (takesRequest && callees.some((c) => MACHINE_RE.test(c.replace(BARE_SECRET_NAME_RE, " ")))) return "machine";
  return null;
}

/**
 * The positions of `name`'s parameters that its own body uses as a filter
 * value: `.eq("workspace_id", p)`, `.match({ col: p })`, `where: { col: p }`
 * or `where: { p }`. Used to credit a trusted id handed to a data helper
 * (class C, inspector computeSetupStatus(workspaceId)).
 */
export function filteredParameters(content: string, name: string): Set<number> {
  const sf = ts.createSourceFile("helper.ts", content, ts.ScriptTarget.Latest, true);
  let fn: ts.SignatureDeclaration & { body?: ts.Node } | undefined;
  const visit = (n: ts.Node) => {
    if (fn) return;
    if (ts.isFunctionDeclaration(n) && n.name?.text === name) fn = n;
    else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer
      && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) fn = n.initializer;
    else ts.forEachChild(n, visit);
  };
  visit(sf);
  const out = new Set<number>();
  if (!fn?.body) return out;
  const body = fn.body.getText(sf);
  fn.parameters.forEach((p, i) => {
    if (!ts.isIdentifier(p.name)) return;
    const v = esc(p.name.text);
    const filter = new RegExp(
      `\\.(?:eq|match|filter)\\s*\\(\\s*["'\`]\\w+["'\`]\\s*,\\s*${v}\\s*\\)`
      + `|\\bwhere\\s*:\\s*\\{[^}]*(?:\\b\\w+\\s*:\\s*${v}\\b|[{,]\\s*${v}\\s*[,}])`);
    if (filter.test(body)) out.add(i);
  });
  return out;
}

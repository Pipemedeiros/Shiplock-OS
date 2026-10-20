import ts from "typescript";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport } from "@/lib/deep/clientExposure";

/**
 * CROSS-TENANT MACHINE-GATED ENDPOINTS ARE NOTES, NOT FINDINGS.
 *
 * A cron or webhook endpoint that reads every tenant's rows because that is
 * what a cleanup job does is correct behaviour. Reporting it as a critical
 * spends the customer's trust to demonstrate comprehension. But the fact layer
 * already read the gate, and saying nothing throws that away — so it becomes an
 * inventory statement: named file, named mechanism, explicit no action.
 *
 * THE EMISSION BAR IS HIGHER THAN THE FINDING BAR, and the reason is asymmetric
 * consequence. A critical invites the customer to check. A note tells them not
 * to. A wrong critical costs an argument; a wrong note costs the thing the
 * argument would have found. Two rules follow, and both are refusals:
 *
 *  1. Name the file AND the mechanism, or emit nothing. This is what
 *     disqualified the 46 witness routes whose "gate" was a Zod schema field.
 *
 *  2. The gate must run UNCONDITIONALLY. Measured across a stratified fifteen
 *     on 2026-09-08: 8 verify only on Vercel, because corpus-b's and corpus-a's
 *     `verifyQstashSignature` both open with
 *     `if (process.env.VERCEL !== "1") { return; }`. On a self-hosted
 *     deployment those endpoints are open. corpus-b and corpus-c both ship
 *     self-hosting, so this is not hypothetical, and the condition is not
 *     visible from the route file — it lives in the helper, which is why this
 *     module follows the call instead of pattern-matching the handler.
 *
 * Deliberately NOT here: anything about whether the endpoint is exposed, and
 * anything inferred. A route whose gate we cannot follow keeps its existing
 * treatment and stays a candidate; unreadable is already disclosed as unknown,
 * and that is survivable in a way a false reassurance is not.
 */

export interface CrossTenantNote {
  /** The route this is about. */
  path: string;
  /** The file the gate is written in — required by rule 1. */
  file: string;
  /** What the gate does, in words — required by rule 1. */
  mechanism: string;
}

/**
 * Mechanisms we can describe. Order matters: the most specific description of
 * the same code wins, so an Upstash receiver is not reported as "a signature
 * check" when we can say which one.
 */
const MECHANISMS: { re: RegExp; mechanism: string; calls: string[] }[] = [
  { re: /\breceiver\s*\.\s*verify\s*\(/, mechanism: "an Upstash QStash signature check", calls: ["verify"] },
  { re: /\bstripe\s*\.\s*(?:webhooks\s*\.\s*constructEvent|parseThinEvent)\s*\(/, mechanism: "a Stripe webhook signature check", calls: ["constructEvent", "parseThinEvent"] },
  { re: /createHmac\s*\(/, mechanism: "an HMAC signature check", calls: ["createHmac"] },
  { re: /timingSafe(?:Equal|Compare)\s*\(/, mechanism: "a constant-time secret comparison", calls: ["timingSafeEqual", "timingSafeCompare"] },
  // These two ARE an `if` on process.env rather than a call, so there is no
  // callee to ask about — asking would flag the gate's own rejection branch.
  { re: /Bearer\s*\$\{\s*process\.env\.[A-Z0-9_]+/, mechanism: "a shared-secret bearer token check", calls: [] },
  { re: /!==\s*process\.env\.[A-Z0-9_]+|process\.env\.[A-Z0-9_]+\s*!==/, mechanism: "a shared-secret comparison", calls: [] },
];

/**
 * A CALL to `verifyWebhookSignature(...)` is not a mechanism, it is a
 * delegation: the check lives in the callee, and so does the environment
 * condition that decides whether it runs. Treating the call as the mechanism
 * read corpus-a's and corpus-b's routes as gated without ever opening
 * `verify-qstash.ts`, which is exactly the 8-of-15 case this module exists to
 * refuse. So this pattern only tells us WHERE to look next.
 */
const DELEGATES_RE = /\bverify[A-Z]\w*(?:Signature|Secret|Token)\s*\(/;

const match = (src: string) => MECHANISMS.find((m) => m.re.test(src)) ?? null;
const describe = (src: string): string | null => match(src)?.mechanism ?? null;

/** `process.env` anywhere inside an expression. */
function mentionsEnv(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isPropertyAccessExpression(n) && n.expression.getText().trim() === "process" && n.name.text === "env") found = true;
    else if (ts.isElementAccessExpression(n) && n.expression.getText().includes("process.env")) found = true;
    else ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

const parse = (f: RepoFile) => ts.createSourceFile(f.path, f.content, ts.ScriptTarget.Latest, true);

/**
 * A function that gives up when an environment variable says so.
 *
 * `if (process.env.VERCEL !== "1") { return; }` at the top of a verifier means
 * every caller is ungated off Vercel.
 *
 * The discriminator is REJECTION, not the bare return. Both of these are an
 * `if` on `process.env` containing `return;`:
 *
 *   if (process.env.VERCEL !== "1") { return; }                       // skip
 *   if (token !== process.env.INTERNAL_API_KEY) { res.status(401); return; }  // gate
 *
 * The second IS the gate — it is the most common way to write one. Suppressing
 * it silenced corpus-b's two INTERNAL_API_KEY routes on the first run here. A
 * branch that answers 401/403, throws, or returns an error Response is
 * rejecting the caller; a branch that returns nothing at all is giving up on
 * checking.
 */
const REJECTS_RE = /\b(401|403)\b|Unauthorized|Forbidden|\bthrow\b/i;
function skipsOnEnvironment(sf: ts.SourceFile): boolean {
  let skips = false;
  const visit = (n: ts.Node): void => {
    if (skips) return;
    if (ts.isIfStatement(n) && mentionsEnv(n.expression)) {
      const bails = (branch: ts.Statement | undefined): boolean => {
        if (!branch) return false;
        // A branch that rejects the caller is the gate, not a skip of it.
        if (REJECTS_RE.test(branch.getText())) return false;
        let bare = false;
        const look = (x: ts.Node): void => {
          if (bare) return;
          if (ts.isReturnStatement(x) && x.expression === undefined) bare = true;
          else if (!ts.isFunctionLike(x)) ts.forEachChild(x, look);
        };
        look(branch);
        return bare;
      };
      if (bails(n.thenStatement) || bails(n.elseStatement)) { skips = true; return; }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return skips;
}

/** Is any call to `name` inside an `if` that tests `process.env`? */
function callIsEnvConditional(sf: ts.SourceFile, names: Set<string>): boolean {
  let conditional = false;
  const visit = (n: ts.Node, guarded: boolean): void => {
    if (conditional) return;
    if (ts.isCallExpression(n)) {
      const callee = n.expression;
      const text = ts.isPropertyAccessExpression(callee) ? callee.name.text : callee.getText();
      if (guarded && names.has(text)) { conditional = true; return; }
    }
    if (ts.isIfStatement(n)) {
      const g = guarded || mentionsEnv(n.expression);
      visit(n.expression, guarded);
      visit(n.thenStatement, g);
      if (n.elseStatement) visit(n.elseStatement, g);
      return;
    }
    ts.forEachChild(n, (c) => visit(c, guarded));
  };
  visit(sf, false);
  return conditional;
}

/** Names called anywhere in the file, so a helper can be matched to its import. */
function calledNames(sf: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      const c = n.expression;
      out.add(ts.isPropertyAccessExpression(c) ? c.name.text : c.getText());
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

/**
 * The notes for one repository's routes.
 *
 * `byPath` is the read file set. A helper outside it cannot be checked for an
 * environment skip, so its route is not notable — refusing on an unfollowable
 * call is the whole point of rule 2.
 */
export function crossTenantNotes(routes: RouteFact[], byPath: Map<string, RepoFile>): CrossTenantNote[] {
  const out: CrossTenantNote[] = [];

  for (const route of routes) {
    // Population A only: the gate was matched in the route's own file, the
    // query is not narrowed, and there is data to be cross-tenant about.
    if (!route.machineGated || route.ownershipFiltered || route.tables.length === 0) continue;

    const entry = byPath.get(route.file);
    if (!entry) continue;
    const sf = parse(entry);

    // 1. Written inline in the route file. Only the MECHANISM's own call is
    //    asked about: passing every call in the file made the gate's own
    //    `res.status(401)` branch look like an environment condition and
    //    silenced corpus-b's two INTERNAL_API_KEY routes.
    const inline = match(entry.content);
    if (inline) {
      if (skipsOnEnvironment(sf)) continue;
      if (inline.calls.length > 0 && callIsEnvConditional(sf, new Set(inline.calls))) continue;
      out.push({ path: route.path, file: route.file, mechanism: inline.mechanism });
      continue;
    }

    // 2. In a helper the route calls. Only reached when the route delegates —
    //    and an unfollowable helper is a refusal, not a guess.
    if (!DELEGATES_RE.test(entry.content)) continue;
    const called = calledNames(sf);
    let noted = false;
    for (const stmt of sf.statements) {
      if (noted || !ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const clause = stmt.importClause?.namedBindings;
      const names = clause && ts.isNamedImports(clause) ? clause.elements.map((e) => e.name.text) : [];
      if (!names.some((n) => called.has(n))) continue;

      const resolved = resolveImport(route.file, stmt.moduleSpecifier.text, byPath);
      const helper = resolved ? byPath.get(resolved) : undefined;
      if (!helper) continue;

      const mechanism = describe(helper.content);
      if (!mechanism) continue;
      // Rule 2, both halves: the helper must not bail on an env var, and the
      // call site must not be wrapped in one.
      if (skipsOnEnvironment(parse(helper))) continue;
      if (callIsEnvConditional(sf, new Set(names))) continue;

      out.push({ path: route.path, file: helper.path, mechanism });
      noted = true;
    }
  }

  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** The customer-facing sentence. Named file, named mechanism, explicit no action. */
export function renderCrossTenantNote(note: CrossTenantNote): string {
  return (
    `${note.path} verifies ${note.mechanism} in ${note.file} before doing anything, ` +
    `and then reads or writes across every tenant. Processing all tenants is what this kind of ` +
    `endpoint is for. No action needed; it is listed so you can see we read the gate, not ` +
    `because anything is wrong with it.`
  );
}

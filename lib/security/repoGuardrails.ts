// Offline repository policy checker. Inputs are tracked text, never executed.
// Syntax pins are deliberately conservative: changing reviewed trust-boundary
// code requires reviewing its registry digest as well as running its tests.
import { createHash } from "node:crypto";
import { posix } from "node:path";
import ts from "typescript";
import { z } from "zod";

const pathSchema = z.string().min(1).refine(p => !p.startsWith("/") && !p.split("/").includes(".."));
const pins = z.record(pathSchema, z.string().regex(/^[a-f0-9]{64}$/));
const base = {
  id: z.string().regex(/^[a-z][a-z0-9-]+$/), statement: z.string().min(10), why: z.string().min(10),
  severity: z.enum(["block", "warn"]), scope: z.array(pathSchema).min(1),
  exclude: z.array(pathSchema).default([]),
  enforcedBy: z.object({ file: pathSchema, test: z.string().min(1) }).strict(),
};
const ruleSchema = z.discriminatedUnion("kind", [
  z.object({ ...base, kind: z.literal("forbidden_pattern"), check: z.enum(["client-server", "model-clients", "model-keys", "secrets", "provider-writes"]), sourcePins: pins.optional(),
    // Reviewed fake secrets in detector tests, by SHA-256 of the exact value. Adding one is a visible review.
    allowedValueDigests: z.array(z.string().regex(/^[a-f0-9]{64}$/)).optional() }).strict(),
  z.object({ ...base, kind: z.literal("required_pattern"), check: z.literal("cookie-origin"), sourcePins: pins.optional(), importers: z.record(pathSchema, z.array(pathSchema)).optional() }).strict(),
  z.object({ ...base, kind: z.literal("file_policy"), check: z.enum(["markdown", "migrations", "migration-loads", "agents-approval"]), sourcePins: pins.optional(), allowed: z.array(pathSchema).optional() }).strict(),
  z.object({ ...base, kind: z.literal("existing_test"), testFile: pathSchema, testName: z.string().min(1), assertionDigest: z.string().regex(/^[a-f0-9]{64}$/), importers: z.record(pathSchema, z.array(pathSchema)).optional(), sourcePins: pins.optional() }).strict(),
]);
export const registrySchema = z.object({ version: z.literal(1), rules: z.array(ruleSchema).min(15) }).strict().superRefine((r, ctx) => {
  if (new Set(r.rules.map(rule => rule.id)).size !== r.rules.length) ctx.addIssue({ code: "custom", message: "Duplicate rule ids" });
});
export type Guardrail = z.infer<typeof ruleSchema>;
export type Snapshot = Map<string, string>;
export type Violation = { rule: string; path: string; reason: string; severity: "block" | "warn" };
export type CommitEvidence = { changedPaths: string[]; message: string };

export const FIXTURES = "lib/security/guardrailFixtures/";
export const isSource = (p: string) => /\.[cm]?[jt]sx?$/.test(p);
export const isTest = (p: string) => /(?:^|\/)(?:[^/]*\.(?:test|spec)\.[^/]+|__tests__\/|fixtures?\/)/i.test(p);
export function matches(path: string, glob: string): boolean {
  // Small documented glob language: *, **, **/ and ?. No dependency or shell.
  let pattern = "";
  for (let i = 0; i < glob.length; i++) {
    if (glob[i] === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") { pattern += "(?:.*/)?"; i += 2; }
      else { pattern += ".*"; i++; }
    } else if (glob[i] === "*") pattern += "[^/]*";
    else if (glob[i] === "?") pattern += "[^/]";
    else pattern += glob[i].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${pattern}$`).test(path);
}
const syntaxCache = new Map<string, ts.SourceFile>();
function source(path: string, content: string): ts.SourceFile {
  const key = path + ":" + createHash("sha256").update(content).digest("hex");
  let sf = syntaxCache.get(key);
  if (!sf) { sf = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true); syntaxCache.set(key, sf); }
  return sf;
}
export function syntaxDigest(path: string, content: string): string {
  return createHash("sha256").update(ts.createPrinter({ removeComments: true }).printFile(source(path, content))).digest("hex");
}
const nodeCache = new WeakMap<ts.Node, ts.Node[]>();
function nodes(root: ts.Node): ts.Node[] {
  const cached = nodeCache.get(root);
  if (cached) return cached;
  const out: ts.Node[] = [];
  const visit = (n: ts.Node) => { out.push(n); ts.forEachChild(n, visit); };
  visit(root); nodeCache.set(root, out); return out;
}
const unwrap = (n: ts.Node): ts.Node => ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression(n) || ts.isAwaitExpression(n) ? unwrap(n.expression) : n;

const declarationCache = new WeakMap<ts.SourceFile, Map<string, ts.VariableDeclaration>>();
class Project {
  private parsed = new Map<string, ts.SourceFile>();
  constructor(readonly files: Snapshot) {}
  sf(path: string) {
    let sf = this.parsed.get(path);
    if (!sf) { sf = source(path, this.files.get(path) ?? ""); this.parsed.set(path, sf); }
    return sf;
  }
  resolve(from: string, spec: string): string {
    const base = spec.startsWith("@/") ? spec.slice(2) : spec.startsWith(".") ? posix.normalize(posix.join(posix.dirname(from), spec)) : spec;
    return [base, ...[".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.tsx"].map(s => base + s)].find(p => this.files.has(p)) ?? base;
  }
  value(path: string, input: ts.Node | undefined, seen = new Set<ts.Node>()): string | undefined {
    if (!input) return undefined;
    const n = unwrap(input);
    if (seen.has(n)) return undefined;
    seen = new Set([...seen, n]);
    if (ts.isStringLiteralLike(n) || ts.isNumericLiteral(n)) return n.text;
    if (ts.isIdentifier(n)) {
      const sf = this.sf(path);
      let declarations = declarationCache.get(sf);
      if (!declarations) {
        declarations = new Map();
        for (const d of nodes(sf)) if (ts.isVariableDeclaration(d) && ts.isIdentifier(d.name) && !declarations.has(d.name.text)) declarations.set(d.name.text, d);
        declarationCache.set(sf, declarations);
      }
      const decl = declarations.get(n.text);
      if (decl && ts.isVariableDeclaration(decl)) return this.value(path, decl.initializer, seen);
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const a = this.value(path, n.left, seen), b = this.value(path, n.right, seen);
      return a !== undefined && b !== undefined ? a + b : undefined;
    }
    if (ts.isTemplateExpression(n)) return n.head.text + n.templateSpans.map(s => (this.value(path, s.expression, seen) ?? "{dynamic}") + s.literal.text).join("");
    if (ts.isComputedPropertyName(n)) return this.value(path, n.expression, seen);
    return undefined;
  }
  imports(path: string): { target: string; node: ts.Node }[] {
    const imports: { target: string; node: ts.Node }[] = [];
    for (const n of nodes(this.sf(path))) {
      let arg: ts.Node | undefined;
      if (ts.isImportDeclaration(n) && !n.importClause?.isTypeOnly) {
        const bindings = n.importClause?.namedBindings;
        if (!n.importClause?.name && bindings && ts.isNamedImports(bindings) && bindings.elements.every(e => e.isTypeOnly)) continue;
        arg = n.moduleSpecifier;
      } else if (ts.isExportDeclaration(n) && !n.isTypeOnly) arg = n.moduleSpecifier;
      else if (ts.isCallExpression(n) && (n.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(n.expression) && n.expression.text === "require"))) arg = n.arguments[0];
      if (arg) imports.push({ target: this.resolve(path, this.value(path, arg) ?? "!unresolved-import"), node: n });
    }
    return imports;
  }
  reachable(path: string, seen = new Set<string>()): Set<string> {
    if (seen.has(path)) return seen;
    seen.add(path);
    for (const edge of this.imports(path)) if (this.files.has(edge.target) && isSource(edge.target)) this.reachable(edge.target, seen);
    return seen;
  }
  property(path: string, n: ts.Node): string | undefined {
    if (ts.isPropertyAccessExpression(n)) return n.name.text;
    if (ts.isElementAccessExpression(n)) return this.value(path, n.argumentExpression);
    return undefined;
  }
  importedName(path: string, input: ts.Node): string | undefined {
    const n = unwrap(input);
    if (!ts.isIdentifier(n)) return undefined;
    for (const stmt of this.sf(path).statements) {
      if (!ts.isImportDeclaration(stmt) || !stmt.importClause) continue;
      const mod = this.value(path, stmt.moduleSpecifier);
      const bindings = stmt.importClause.namedBindings;
      if (bindings && ts.isNamedImports(bindings)) for (const el of bindings.elements) {
        if (el.name.text === n.text) return `${this.resolve(path, mod ?? "")}:${el.propertyName?.text ?? el.name.text}`;
      }
    }
    return undefined;
  }
}

// No exemption for *.test.ts secrets: only data under explicit fixture paths.
// Prefix-only detector definitions and short dummy values are not credentials.
const secretPattern = /(?:sk_live_[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|\bre_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/;

const secretGlobal = new RegExp(secretPattern.source, "g");
// A private key is the key material, not the header line a detector test names.
const PEM_BODY = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}/g;
export const valueDigest = (value: string) => createHash("sha256").update(value).digest("hex");
/** Secret-shaped values, minus the reviewed test fakes listed by digest. */
export function unreviewedSecrets(text: string, allowed: ReadonlySet<string>): string[] {
  return [...text.matchAll(secretGlobal)].map((m) => m[0]).filter((v) => !v.startsWith("-----BEGIN"))
    .concat([...text.matchAll(PEM_BODY)].map((m) => m[0])).filter((v) => !allowed.has(valueDigest(v)));
}

const MODEL_SDK = /^(?:@anthropic-ai\/|openai(?:$|\/)|@ai-sdk\/|ai$|@google\/(?:generative-ai|genai)|@mistralai\/|cohere-ai|groq-sdk)/;
const MODEL_HOST = /api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com/;
const MODEL_KEY = /^(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|SHIPLOCK_FUNDED_[A-Z_]+)$/;

export function checkRule(rule: Guardrail, files: Snapshot, commits: CommitEvidence[] = []): Violation[] {
  const hits: Violation[] = [];
  const hit = (path: string, reason: string) => hits.push({ rule: rule.id, path, reason, severity: rule.severity });
  const selected = [...files.keys()].filter(p => !p.startsWith(FIXTURES) && rule.scope.some(g => matches(p, g)) && !rule.exclude.some(g => matches(p, g)));
  const project = new Project(files);
  const prod = selected.filter(p => isSource(p) && !isTest(p));
  if ("sourcePins" in rule && rule.sourcePins) for (const [path, digest] of Object.entries(rule.sourcePins)) {
    if (!files.has(path) || syntaxDigest(path, files.get(path)!) !== digest) hit(path, "Reviewed executable syntax changed or disappeared");
  }
  if ("importers" in rule && rule.importers) for (const p of prod) for (const edge of project.imports(p)) {
    for (const [boundary, allowed] of Object.entries(rule.importers)) {
      const [target, symbol] = boundary.split("#");
      if (edge.target !== target) continue;
      if (symbol && ts.isImportDeclaration(edge.node)) {
        const clause = edge.node.importClause?.namedBindings;
        if (clause && ts.isNamedImports(clause) && !clause.elements.some(e => (e.propertyName?.text ?? e.name.text) === symbol)) continue;
      }
      if (!allowed.includes(p)) hit(p, `Unreviewed caller of ${boundary}`);
    }
  }
  if (rule.kind === "existing_test") {
    const text = files.get(rule.testFile);
    if (!text) hit(rule.testFile, "Enforcing test file missing");
    else {
      const sf = project.sf(rule.testFile);
      const names = nodes(sf).filter(ts.isCallExpression).map(n => project.value(rule.testFile, n.arguments[0]));
      if (!names.includes(rule.testName)) hit(rule.testFile, "Named enforcing test missing");
      if (syntaxDigest(rule.testFile, text) !== rule.assertionDigest) hit(rule.testFile, "Reviewed assertions or executable test setup changed");
    }
  } else if (rule.kind === "file_policy") {
    if (rule.check === "markdown") for (const p of selected) if (/\.(md|markdown)$/i.test(p) && !rule.allowed?.some(g => matches(p, g))) hit(p, "Extra project Markdown");
    if (rule.check === "agents-approval") for (const commit of commits) if (commit.changedPaths.includes("AGENTS.md") && !commit.message.includes("Felipe approved")) hit("AGENTS.md", "Commit changes AGENTS.md without Felipe approved in its message");
    if (rule.check === "migrations") {
      const migrations = selected.filter(p => p.endsWith(".sql"));
      const numbers = migrations.map(p => /^supabase\/migrations\/(\d{3})_.+\.sql$/.exec(p)?.[1]).map(n => Number(n));
      if (numbers.some(n => !Number.isInteger(n) || n < 1)) hit("supabase/migrations", "Invalid migration filename");
      const sorted = numbers.sort((a, b) => a - b);
      if (sorted.some((n, i) => n !== i + 1)) hit("supabase/migrations", "Migration gap or duplicate");
    }
    if (rule.check === "migration-loads") {
      const loader = "scripts/test-foundation-sql.mjs";
      const sf = project.sf(loader);
      const loads = nodes(sf).filter(ts.isCallExpression).filter(n => ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "exec");
      for (const path of selected.filter(p => /^supabase\/migrations\/(\d{3})_.*\.sql$/.test(p) && Number(p.slice(20, 23)) > 95)) {
        if (!loads.some(call => nodes(call).some(n => ts.isStringLiteralLike(n) && n.text === `../${path}`))) hit(path, "New migration is not executed by the local SQL suite");
      }
    }
  } else if (rule.kind === "required_pattern") {
    if (rule.check === "cookie-origin") {
      const listing = "lib/security/sameOrigin.routes.test.ts";
      const listed = project.imports(listing).map(e => e.target);
      for (const path of prod.filter(p => /^app\/api\/.*\/route\.[jt]s$/.test(p))) {
        const sf = project.sf(path);
        const mutations = sf.statements.filter(ts.isFunctionDeclaration).filter(n => n.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) && /^(POST|PUT|PATCH|DELETE)$/.test(n.name?.text ?? ""));
        const closure = project.reachable(path);
        const cookie = [...closure].some(p => /(?:supabaseServer|deep\/proGate|dashboard|betterAuth)\.ts$/.test(p)) || listed.includes(path);
        if (!cookie) continue;
        for (const fn of mutations) {
          const first = fn.body?.statements[0], second = fn.body?.statements[1];
          const decl = first && ts.isVariableStatement(first) ? first.declarationList.declarations[0] : undefined;
          const call = decl?.initializer && ts.isCallExpression(decl.initializer) ? decl.initializer : undefined;
          const actualGuard = call && project.importedName(path, call.expression) === "lib/security/sameOrigin.ts:crossSiteRefusal";
          const returnsRefusal = decl && ts.isIdentifier(decl.name) && second && ts.isIfStatement(second) && ts.isIdentifier(second.expression) && second.expression.text === decl.name.text && ts.isReturnStatement(second.thenStatement) && second.thenStatement.expression?.getText(sf) === decl.name.text;
          if (!actualGuard || !returnsRefusal) hit(path, `${fn.name?.text}: first statements must call and return the real crossSiteRefusal`);
          if (!listed.includes(path)) hit(path, `${fn.name?.text}: missing from sameOrigin.routes.test.ts`);
        }
      }
    }
  } else if (rule.kind === "forbidden_pattern") {
    if (rule.check === "secrets") for (const p of selected) {
      const text = files.get(p)!;
      const allowed = new Set(rule.allowedValueDigests ?? []);
      const hasRaw = unreviewedSecrets(text, allowed).length > 0;
      const hasFolded = isSource(p) && nodes(project.sf(p)).some(n => {
        const value = project.value(p, n); return value !== undefined && unreviewedSecrets(value, allowed).length > 0;
      });
      if (hasRaw || hasFolded) hit(p, "Secret-shaped value (redacted)");
    }
    if (rule.check === "client-server") for (const p of prod) {
      const sf = project.sf(p);
      const client = sf.statements.some(n => ts.isExpressionStatement(n) && ts.isStringLiteral(n.expression) && n.expression.text === "use client");
      if (!client) continue;
      for (const dep of project.reachable(p)) {
        if (dep === "lib/crypto.ts") { hit(p, `Client reaches ${dep}`); break; }
        const unsafe = nodes(project.sf(dep)).some(n => (ts.isIdentifier(n) && n.text === "getSupabaseAdmin") || project.property(dep, n) === "SUPABASE_SERVICE_ROLE_KEY");
        if (unsafe) { hit(p, `Client reaches server secret or admin through ${dep}`); break; }
      }
    }
    // ShipLock makes no model call (Felipe, 2026-10-01). Runtime SDK imports
    // (aliased, barrel, dynamic or require) and folded model API hosts are
    // checked rather than the spelling of a constructor; a module expression
    // that cannot be resolved could hide one, so it fails too.
    if (rule.check === "model-clients") for (const p of prod) {
      for (const edge of project.imports(p)) {
        if (MODEL_SDK.test(edge.target)) hit(p, `Runtime model SDK import ${edge.target}`);
        if (edge.target === "!unresolved-import") hit(p, "Unresolvable module expression could hide a model SDK");
      }
      if (nodes(project.sf(p)).some(n => { const v = project.value(p, n); return v !== undefined && MODEL_HOST.test(v); })) hit(p, "Model API host");
    }
    if (rule.check === "model-keys") for (const p of prod) {
      if (nodes(project.sf(p)).some(n => MODEL_KEY.test(project.property(p, n) ?? ""))) hit(p, "Reads a model key or a funded-call switch");
    }
    if (rule.check === "provider-writes") for (const p of prod) {
      const sf = project.sf(p), all = nodes(sf);
      // Fold concatenations, escaped literals and template static portions.
      const strings = all.filter(n => ts.isStringLiteralLike(n) || ts.isBinaryExpression(n) || ts.isTemplateExpression(n)).map(n => project.value(p, n)).filter((v): v is string => v !== undefined);
      if (strings.some(v => /(?:\/pulls\/[^/]+\/merge|\/repos\/.*\/merges)(?:$|[?{])/i.test(v))) hit(p, "GitHub merge endpoint");
      // A GitHub merge is pulls.merge / repos.merge; a data option named "merge" is not.
      const methodCall = all.some(n => {
        if (!ts.isCallExpression(n)) return false;
        const name = project.property(p, n.expression) ?? "";
        if (/^(createDeployment|updateEnvironmentVariable|updateProject|updateAuthConfig)$/.test(name)) return true;
        const target = ts.isPropertyAccessExpression(n.expression) || ts.isElementAccessExpression(n.expression) ? n.expression.expression.getText(sf) : "";
        return name === "merge" && /\b(pulls|repos)$/.test(target.replace(/\s+/g, ""));
      });
      if (methodCall) hit(p, "Forbidden provider mutation API");
      // Each fetch to a provider literal is checked separately; read-only SQL
      // POST is admitted only by the pinned read-only collector, never a file
      // exemption that would let a second unguarded call slip through.
      for (const call of all.filter(ts.isCallExpression)) {
        if (!call.arguments[0]) continue;
        const url = project.value(p, call.arguments[0]);
        if (!url || !/api\.(?:vercel\.com|supabase\.com)/.test(url)) continue;
        const options = call.arguments[1];
        const method = options ? nodes(options).filter(ts.isPropertyAssignment).find(n => n.name.getText(sf) === "method") : undefined;
        const value = method ? project.value(p, method.initializer) : "GET";
        if (value === "GET" || value === "HEAD" || /\/oauth\/(?:token|access_token)$/.test(url)) continue;
        const sqlRead = /api\.supabase\.com.*\/database\/query$/.test(url) && p === "lib/deep/supabaseMgmt.ts" && rule.sourcePins?.[p] === syntaxDigest(p, files.get(p)!);
        // A reviewed exception is a pinned file (any edit re-opens review), e.g. the
        // dormant disposable-branch prover, whose switch file is pinned with it.
        const reviewed = p !== "lib/deep/supabaseMgmt.ts" && rule.sourcePins?.[p] === syntaxDigest(p, files.get(p)!);
        if (!sqlRead && !reviewed) hit(p, "Provider deployment, environment or management write");
      }
    }
  }
  return hits;
}

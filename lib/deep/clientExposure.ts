import type { GithubFinding, RepoFile } from "./githubScan";
import { isTestPath, looksSynthetic, hasParseablePrivateKey } from "./githubScan";
import { resolveViaTsconfigPaths } from "@/lib/graph/tsconfigPaths";

// Source-reading helpers shared by the graph layer keep their existing semantics.
// Only direct credential values are findings; names and import reachability are not.
const CODE_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;

export function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:'"`\\])\/\/[^\n]*/g, "$1");
}

/**
 * Where the string literals are.
 *
 * A single pass tracking quote state and escapes. Comments are stripped
 * upstream by stripComments; this is the other half of "is this token code, or
 * is it text that happens to look like code".
 *
 * Lives here because this file is where the source-reading helpers live —
 * lib/graph/routeInventory.ts already imports stripComments and resolveImport
 * from it, and it needs this one for the same reason.
 */
export function stringLiteralRanges(src: string): { start: number; end: number; quote: string }[] {
  const ranges: { start: number; end: number; quote: string }[] = [];
  let quote: string | null = null;
  let start = 0;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quote) {
      if (ch === "\\") { i++; continue; }
      if (ch === quote) { ranges.push({ start, end: i, quote }); quote = null; }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; start = i + 1; }
  }
  if (quote) ranges.push({ start, end: src.length, quote });

  return ranges;
}

/**
 * Which byte offsets sit inside a string literal.
 *
 * A query written inside a string is not a query. `const sample =
 * "admin.from('orders').select('*')"` is documentation, a code sample, or a
 * generator template, and reading it as data access reported an endpoint that
 * returns a constant as CRITICAL for exposing a table.
 */
export function stringSpans(src: string): (index: number) => boolean {
  const inside = new Uint8Array(src.length);
  for (const { start, end } of stringLiteralRanges(src)) {
    for (let i = start; i < end && i < inside.length; i++) inside[i] = 1;
  }
  return (index: number) => index < inside.length && inside[index] === 1;
}

const EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const INDEXES = ["/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

/** Normalises `a/b/../c` and `./` segments without depending on node:path. */
function normalisePath(p: string): string {
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return out.join("/");
}

/**
 * Resolves a LOCAL import specifier to a path in the repo file set. Returns
 * null for bare package imports — a node_modules dependency is the dependency
 * scanner's job, not this one.
 */
export function resolveImport(fromPath: string, spec: string, byPath: Map<string, RepoFile>): string | null {
  let base: string | null = null;
  if (spec.startsWith("@/")) {
    base = spec.slice(2);
  } else if (spec.startsWith("~/")) {
    base = spec.slice(2);
  } else if (spec.startsWith(".")) {
    const dir = fromPath.split("/").slice(0, -1).join("/");
    base = normalisePath(`${dir}/${spec}`);
  }

  // `@/lib/x` may live at `lib/x` or `src/lib/x` depending on the project.
  if (base !== null) {
    for (const prefix of ["", "src/", "app/"]) {
      for (const ext of EXTS) {
        const cand = `${prefix}${base}${ext}`;
        if (byPath.has(cand)) return cand;
      }
      for (const idx of INDEXES) {
        const cand = `${prefix}${base}${idx}`;
        if (byPath.has(cand)) return cand;
      }
    }
  }

  // A workspace: apps/web/app/... importing `@/lib/auth` means apps/web/lib/auth,
  // and only the repository's own tsconfig knows that. Tried last so the
  // single-app layout above keeps resolving exactly as it did.
  return resolveViaTsconfigPaths(fromPath, spec, byPath);
}

/**
 * Decodes a Supabase legacy JWT's `role` claim. A key called
 * NEXT_PUBLIC_SUPABASE_ANON_KEY that actually holds the service-role JWT is
 * both the most catastrophic and the most invisible version of this bug — the
 * two keys sit next to each other in the Supabase dashboard and look identical
 * at a glance. Only the decoded payload tells them apart.
 */
export function jwtRole(token: string): string | null {
  const m = /\beyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+/.exec(token);
  if (!m) return null;
  try {
    const b64 = m[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = typeof atob === "function"
      ? atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="))
      : Buffer.from(b64, "base64").toString("utf8");
    const role = (JSON.parse(json) as { role?: unknown }).role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

const CLIENT_PREFIX = "(?:NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_|PUBLIC_)";
const ENVISH_RE = /(^|\/)(\.env(\.[A-Za-z0-9_-]+)?|.*\.(env|ini|conf|cfg|toml|yaml|yml|json))$/i;
/** Value shapes that are a secret no matter what the variable is called. */
const SECRET_VALUE_RES: { re: RegExp; label: string }[] = [
  { re: /\bsb_secret_[A-Za-z0-9_-]{10,}/, label: "a Supabase secret key" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, label: "a PEM private key" },
  { re: /\bsk_live_[A-Za-z0-9]{10,}/, label: "a live Stripe secret key" },
  { re: /\bsk_test_[A-Za-z0-9]{10,}/, label: "a test Stripe secret key" },
  { re: /\bsk-ant-[A-Za-z0-9_-]{10,}/, label: "an Anthropic API key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "an AWS access key id" },
  { re: /\bghp_[A-Za-z0-9]{20,}/, label: "a GitHub personal access token" },
];

/** Placeholder values provide no credential evidence. */
const PLACEHOLDER_RE =
  /^(|<.*>|\$\{.*\}|your[-_ ].*|my[-_ ].*|x{3,}|\.{3,}|changeme|change[-_]me|todo|tbd|placeholder|example|dummy|fake|secret|password|test|test123|123456|12345678|admin|default|foobar|s3cret)$/i;


/** Direct literal credential evidence only; variable names and import reachability make no claim. */
export function scanPublicCredentialValues(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  const seen = new Set<string>();

  const push = (id: string, severity: GithubFinding["severity"], title: string, consequence: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ id, severity, title, consequence, packageName: null, version: null, vulnId: null, cveId: null });
  };

  for (const file of files) {
    const isCode = CODE_RE.test(file.path);
    if (!isCode && !ENVISH_RE.test(file.path)) continue;
    const src = isCode ? stripComments(file.content) : file.content;

    // Literal fixture placeholders remain silent; real credential values do not.
    const inTest = isTestPath(file.path);

    // ── Signals 2 and 3: the value, whatever the name claims. Assignment form
    // only, since these need a value to inspect.
    const ASSIGN_RE = new RegExp(`\\b(${CLIENT_PREFIX}[A-Z0-9_]+)\\s*[:=]\\s*["']?([^"'\\n\\r]+)`, "g");
    ASSIGN_RE.lastIndex = 0;
    let a: RegExpExecArray | null;
    while ((a = ASSIGN_RE.exec(src)) !== null) {
      const [, name, rawValue] = a;
      const value = rawValue.trim();
      if (!value || PLACEHOLDER_RE.test(value)) continue;
      // A value that just forwards another env var isn't a literal secret.
      if (/^process\.env\b|^import\.meta\.env\b/.test(value)) continue;

      const line = src.slice(src.lastIndexOf("\n", a.index) + 1, src.indexOf("\n", a.index) + 1 || undefined);
      if (inTest && looksSynthetic(value, line)) continue;

      const shape = SECRET_VALUE_RES.find((candidate) => candidate.re.test(value) && (!candidate.label.includes("PEM") || hasParseablePrivateKey(value)));
      if (shape) {
        push(
          `github:public_prefixed_secret_value:${name}:${file.path}`,
          "CRITICAL",
          `${name} holds ${shape.label} (${file.path})`,
          `${name} has a public prefix, so its literal value can appear in client builds, and the value in ${file.path} is ${shape.label}, not a publishable one. If used in browser code, visitors receive the credential and its privileges. Rotate it immediately, then move it to a variable with no public prefix. The variable name doesn't matter here; the prefix and the value do.`
        );
        continue;
      }

      const role = jwtRole(value);
      if (role === "service_role") {
        push(
          `github:public_prefixed_service_jwt:${name}:${file.path}`,
          "CRITICAL",
          `${name} holds a Supabase "${role}" key, not the anon key (${file.path})`,
          `The key in ${name} decodes to role "${role}". A service_role key ignores Row Level Security entirely; it can read and write every row in every table. Because ${name} has a public prefix, that key can appear in your browser bundle when used in client code. The anon and service-role keys sit next to each other in the Supabase dashboard and look identical, which is exactly how this happens. Rotate the service-role key now, and put the anon key here instead.`
        );
      }
    }

  }

  return out;
}

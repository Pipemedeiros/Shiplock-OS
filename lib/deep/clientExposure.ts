import { isTestPath, looksSynthetic, type GithubFinding, type RepoFile } from "./githubScan";

// C10 + C11 from CHECK-SPEC.md §4 — the two catastrophic, stack-specific
// exposures. Both have the same shape of consequence: a credential that was
// only ever supposed to exist on a server ends up inlined into JavaScript that
// every visitor downloads. There is no "partially leaked" state. Whoever views
// source has the key, and with a Supabase service-role key that means every row
// in every table, RLS bypassed entirely.
//
// This is the single most common catastrophic mistake in AI-assisted Next.js
// apps, because the fastest way to make a query "just work" when RLS blocks it
// is to swap the anon key for the service-role key — and the assistant will
// often do exactly that without noting that the file it edited runs in the
// browser.
//
// PURE — no network. Rides the GitHub source layer like sourcePatterns.ts.
//
// Precision discipline, same as the rest of the source layer: only known-bad,
// context-guarded patterns. Comments and strings-in-prose are stripped before
// matching, and legitimately-public values (anon/publishable/PostHog keys) are
// allow-listed by name, so the normal Supabase setup stays silent.

const CODE_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;

// Files that can carry a client-prefixed variable but aren't code we walk.
const ENVISH_RE = /(^|\/)(\.env(\.[A-Za-z0-9_-]+)?|.*\.(env|ini|conf|cfg|toml|yaml|yml|json))$/i;

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id,
  severity,
  title,
  consequence,
  packageName: null,
  version: null,
  vulnId: null,
  cveId: null,
});

/**
 * Strips comments so a pattern can't fire on documentation. A `// don't use
 * SUPABASE_SERVICE_ROLE_KEY here` comment is the OPPOSITE of the bug, and
 * flagging it is exactly the kind of noise that teaches people to ignore us.
 *
 * Deliberately naive about strings containing `//` (a URL inside a string
 * literal loses its tail). That direction of inaccuracy is safe: it can only
 * remove text, and no check here depends on the inside of a URL.
 */
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
export function stringLiteralRanges(src: string): { start: number; end: number }[] {
  const ranges: { start: number; end: number }[] = [];
  let quote: string | null = null;
  let start = 0;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quote) {
      if (ch === "\\") { i++; continue; }
      if (ch === quote) { ranges.push({ start, end: i }); quote = null; }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; start = i + 1; }
  }
  if (quote) ranges.push({ start, end: src.length });

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

// ── C10: a server-only credential reachable from browser code ──────────────

/** `"use client"` / `'use client'` as a real directive — top of file only. */
const USE_CLIENT_RE = /^[\s\S]{0,400}?["']use client["']/;

/**
 * Names that only ever belong on a server. Matching any of these in code that
 * reaches the browser is the finding.
 *
 * `service_role` is included as a bare token because that's the `role` claim in
 * a legacy Supabase service key, and it also catches `createClient(url, key,
 * { auth: ... })` helpers named for it.
 */
const SERVER_ONLY_RE =
  /\b(SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|SERVICE_ROLE|service_role|serviceRoleKey|getSupabaseAdmin|STRIPE_SECRET_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|RESEND_API_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|ENCRYPTION_KEY|CRON_SECRET|GITHUB_WEBHOOK_SECRET|GITHUB_APP_PRIVATE_KEY|JWT_SECRET|SESSION_SECRET|DATABASE_URL|sb_secret_)\b|sb_secret_[A-Za-z0-9_-]{10,}/;

/**
 * The server-only token this source actually USES, or null.
 *
 * A match inside a string literal is usually text about the bug rather than the
 * bug. This detector reported nineteen CRITICALs on ShipLock's own dashboard
 * because a design prototype's sample data describes a finding in prose --
 * "lib/db/admin.ts ... reads DATABASE_URL at module scope" -- and every
 * "use client" page in that tree imports the file holding it. The file it names
 * does not exist in the repository. Nineteen fabricated criticals about a
 * fictional file, on the one account a customer would have been shown.
 *
 * But a blanket "ignore strings" would be wrong in the other direction, and
 * wrong on real code: `process.env["SUPABASE_SERVICE_ROLE_KEY"]` puts the token
 * inside a string and is exactly the bug. So there is one carve-out, and it is
 * the SYNTAX that makes it a lookup rather than anything about the string's
 * contents. The first attempt at this admitted any string whose whole content
 * was a bare identifier, which is also the shape of the prototype's
 * `label: "DATABASE_URL"` -- a caption on a mockup. Requiring the string to sit
 * inside a computed read of an env object is the difference between a program
 * reading a secret and a designer naming one.
 */

/** `process.env[`, `import.meta.env[`, `env?.[` -- a computed env read. */
const ENV_LOOKUP_RE = /\benv\s*\??\.?\s*\[\s*$/;
export function findServerOnly(src: string): string | null {
  const ranges = stringLiteralRanges(src);
  const enclosing = (index: number) =>
    ranges.find((r) => index >= r.start && index < r.end) ?? null;

  const re = new RegExp(SERVER_ONLY_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const range = enclosing(m.index);
    if (!range) return m[0];
    // Inside a string: it counts only as the key of a computed env read.
    const before = src.slice(Math.max(0, range.start - 40), range.start - 1);
    if (ENV_LOOKUP_RE.test(before) && src.slice(range.start, range.end).trim() === m[0]) {
      return m[0];
    }
  }
  return null;
}

/** A friendly name for whatever we matched, for the finding text. */
function describeServerOnly(src: string): string {
  const hit = findServerOnly(src) ?? "a server-only credential";
  if (/service_?role|sb_secret_/i.test(hit)) return "your Supabase service-role key";
  if (/getSupabaseAdmin/.test(hit)) return "the service-role Supabase client (getSupabaseAdmin)";
  if (/DATABASE_URL/.test(hit)) return "your database connection string";
  return `${hit} (a server-only secret)`;
}

// TYPE-ONLY IMPORTS ARE EXCLUDED. `import type { X } from "./server"` is erased
// by TypeScript at compile time — nothing from that module reaches the browser,
// so following it would be reasoning about code that does not exist at runtime.
// Found by running this detector against ShipLock's own codebase: it reported
// components/d/TrafficPulse.tsx as leaking the service-role key through a type
// import of an interface. Telling a customer to rotate their service-role key
// because of an erased import would be a false positive on the single
// highest-severity finding we produce.
const IMPORT_RE = /(?:import|export)(?!\s+type\s)[\s\S]{0,200}?from\s*["']([^"']+)["']|require\s*\(\s*["']([^"']+)["']\s*\)|import\s*\(\s*["']([^"']+)["']\s*\)/g;

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
  let base: string;
  if (spec.startsWith("@/")) {
    base = spec.slice(2);
  } else if (spec.startsWith("~/")) {
    base = spec.slice(2);
  } else if (spec.startsWith(".")) {
    const dir = fromPath.split("/").slice(0, -1).join("/");
    base = normalisePath(`${dir}/${spec}`);
  } else {
    return null; // bare package specifier
  }

  // `@/lib/x` may live at `lib/x` or `src/lib/x` depending on the project.
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
  return null;
}

/** How far we chase an import chain from a client component. */
const MAX_DEPTH = 4;

/**
 * C10 — a service-role client (or any server-only secret) reachable from a
 * `"use client"` component.
 *
 * Two cases, and the second is the one everybody misses:
 *  1. The client component itself reads the secret. Obvious once pointed at.
 *  2. The client component imports a module that reads it. Next.js inlines the
 *     whole reachable module graph into the browser bundle, so a shared
 *     `lib/supabase.ts` that builds an admin client at module scope leaks the
 *     key the moment ONE client component imports anything from it — even a
 *     type or an unrelated helper.
 *
 * Case 2 is why this walks imports instead of just grepping client files.
 */
export function scanServerSecretsInClientCode(files: RepoFile[]): GithubFinding[] {
  const code = files.filter((file) => CODE_RE.test(file.path));
  const byPath = new Map(code.map((file) => [file.path, file]));
  // Strip once, reuse across every chain that touches the file.
  const stripped = new Map(code.map((file) => [file.path, stripComments(file.content)]));

  const out: GithubFinding[] = [];

  for (const entry of code) {
    // Tested against RAW content, not the stripped copy: `"use client"` only
    // counts as a directive at the top of the file, and stripping shifts offsets.
    if (!USE_CLIENT_RE.test(entry.content)) continue;

    // BFS the import graph from this client component.
    const seen = new Set<string>([entry.path]);
    let frontier: { path: string; chain: string[] }[] = [{ path: entry.path, chain: [entry.path] }];
    let hit: { path: string; chain: string[] } | null = null;

    for (let depth = 0; depth <= MAX_DEPTH && !hit && frontier.length > 0; depth++) {
      const next: { path: string; chain: string[] }[] = [];
      for (const node of frontier) {
        const src = stripped.get(node.path);
        if (src === undefined) continue;
        if (findServerOnly(src) !== null) {
          hit = node;
          break;
        }
        if (depth === MAX_DEPTH) continue;
        // An import statement quoted inside a string is a code sample, not an
        // edge in the module graph. Same rule as the secret match above, and it
        // matters for the same reason: the prototype data that produced the
        // nineteen false criticals also contains a quoted `import ... from
        // "@/lib/db/admin"` for a module that does not exist.
        const inString = stringSpans(src);
        IMPORT_RE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = IMPORT_RE.exec(src)) !== null) {
          const spec = m[1] ?? m[2] ?? m[3];
          if (!spec) continue;
          // Judge the SPECIFIER's own opening quote, not the match start. The
          // match can begin at a real `export` on line 1 and run into a quoted
          // sample further down, so m.index is code even when the import is
          // text. A genuine import's opening quote is code; the same quote
          // inside a template literal is already within a string span.
          if (inString(m.index + m[0].lastIndexOf(spec) - 1)) continue;
          const resolved = resolveImport(node.path, spec, byPath);
          if (!resolved || seen.has(resolved)) continue;
          seen.add(resolved);
          next.push({ path: resolved, chain: [...node.chain, resolved] });
        }
      }
      frontier = next;
    }

    if (!hit) continue;

    const direct = hit.path === entry.path;
    const secret = describeServerOnly(stripped.get(hit.path)!);
    const via = direct ? "" : ` via ${hit.chain.slice(1).join(" → ")}`;

    out.push(
      f(
        `github:client_server_secret:${entry.path}`,
        "CRITICAL",
        direct
          ? `Server-only secret used in browser code (${entry.path})`
          : `Browser code reaches a server-only secret through an import (${entry.path})`,
        direct
          ? `${entry.path} is a "use client" component — it runs in your visitors' browsers — and it references ${secret}. Anything a client component reads is compiled into the JavaScript you serve, so this value is readable by anyone who opens devtools. If it's the service-role key, it bypasses RLS completely: every row in every table, readable and writable by any visitor. Rotate the key now, then move this code into a server route or Server Component and call it from the client.`
          : `${entry.path} is a "use client" component, and its imports reach ${secret}${via}. Next.js bundles the whole reachable module graph for the browser, so importing anything from that module — even a type or an unrelated helper — ships the secret to every visitor. This is the version of the mistake that looks safe on review, because the client file itself never mentions the key. Rotate it, then split the server-only code into its own module that no client component imports.`
      )
    );
  }

  return out;
}

// ── C11: a secret sitting behind a client-visible prefix ────────────────────

/** Prefixes that inline a variable into the browser bundle, by framework. */
const CLIENT_PREFIX = "(?:NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_|PUBLIC_)";
const CLIENT_VAR_RE = new RegExp(`\\b${CLIENT_PREFIX}[A-Z0-9_]+`, "g");

/**
 * Name tokens that mean server-only. Excludes bare `API_KEY`/`_KEY` on purpose:
 * NEXT_PUBLIC_SUPABASE_ANON_KEY and NEXT_PUBLIC_POSTHOG_KEY are supposed to
 * ship, and flagging them would make this check worthless. Kept in step with
 * lib/deep/envaudit.ts, which applies the same rule to Vercel's env list.
 */
const SECRET_NAME_RE = /(SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|PASSWD|CREDENTIAL)/;

/** Provider keys that are server-only even though they're just called "key". */
const SERVER_PROVIDER_RE =
  /(STRIPE_SECRET|STRIPE_RESTRICTED|ANTHROPIC_API_KEY|OPENAI_API_KEY|RESEND_API_KEY|SENDGRID|TWILIO_AUTH|AWS_SECRET|MAILGUN|GITHUB_TOKEN|SLACK_BOT_TOKEN|OPENROUTER)/;

/**
 * Names that are explicitly fine, checked FIRST so a variable like
 * NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY can never be dragged in by a substring.
 */
const PUBLIC_BY_DESIGN_RE = /(ANON_KEY|PUBLISHABLE|PUBLIC_KEY|POSTHOG|CLIENT_ID|SITE_URL|APP_URL|BASE_URL|GA_|GTM_|SENTRY_DSN|MAPBOX|ALGOLIA_SEARCH)/;

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

/** Placeholders — the name is still wrong, but nothing has actually leaked. */
const PLACEHOLDER_RE =
  /^(|<.*>|\$\{.*\}|your[-_ ].*|my[-_ ].*|x{3,}|\.{3,}|changeme|change[-_]me|todo|tbd|placeholder|example|dummy|fake|secret|password|test|test123|123456|12345678|admin|default|foobar|s3cret)$/i;

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

/**
 * C11 — a secret behind a client-visible prefix.
 *
 * Three independent signals, because each catches a case the others miss:
 *  - the NAME says server-only (NEXT_PUBLIC_STRIPE_SECRET_KEY)
 *  - the VALUE has a secret shape, whatever the name (an anon-key variable
 *    holding sb_secret_…)
 *  - the VALUE is a legacy JWT whose role is service_role (indistinguishable
 *    from the anon key without decoding it)
 */
export function scanPublicPrefixedSecrets(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  const seen = new Set<string>();

  const push = (id: string, severity: GithubFinding["severity"], title: string, consequence: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    out.push(f(id, severity, title, consequence));
  };

  for (const file of files) {
    const isCode = CODE_RE.test(file.path);
    if (!isCode && !ENVISH_RE.test(file.path)) continue;
    const src = isCode ? stripComments(file.content) : file.content;

    // Test scaffolding gets the discipline scanSecrets already applies, and for
    // the reason recorded there: the rule is NOT "skip test files", because a
    // suite talking to a live sandbox needs a real key and silence there is the
    // "thinner audit looks cleaner" failure. The PATH decides how loudly we
    // speak; the VALUE decides whether we speak at all. Without this, this
    // detector reports a detector's own fixtures -- sixteen criticals on this
    // repository, every one of them a variable invented to test this file.
    const inTest = isTestPath(file.path);

    // Variables already reported by a VALUE signal below. The name signal skips
    // these: `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_…` trips both, and the
    // value finding is strictly better evidence — it names the actual key type
    // instead of guessing from the variable name. Reporting both would show the
    // customer one problem twice, which is exactly the triage burden we exist
    // to remove.
    const reportedByValue = new Set<string>();

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

      const shape = SECRET_VALUE_RES.find((candidate) => candidate.re.test(value));
      if (shape) {
        reportedByValue.add(name);
        push(
          `github:public_prefixed_secret_value:${name}:${file.path}`,
          "CRITICAL",
          `${name} holds ${shape.label} (${file.path})`,
          `${name} has a public prefix, so its value is compiled into the JavaScript every visitor downloads — and the value in ${file.path} is ${shape.label}, not a publishable one. Whatever that key can do, any visitor can now do. Rotate it immediately, then move it to a variable with no public prefix. The variable name doesn't matter here; the prefix and the value do.`
        );
        continue;
      }

      const role = jwtRole(value);
      if (role && role !== "anon") {
        reportedByValue.add(name);
        push(
          `github:public_prefixed_service_jwt:${name}:${file.path}`,
          "CRITICAL",
          `${name} holds a Supabase "${role}" key, not the anon key (${file.path})`,
          `The key in ${name} decodes to role "${role}". A service_role key ignores Row Level Security entirely — it can read and write every row in every table. Because ${name} has a public prefix, that key is inlined into your browser bundle and readable by anyone who opens devtools. The anon and service-role keys sit next to each other in the Supabase dashboard and look identical, which is exactly how this happens. Rotate the service-role key now, and put the anon key here instead.`
        );
      }
    }

    // ── Signal 1: the name. Works even where there is no value to inspect,
    // which is the common case in code (a bare process.env read).
    CLIENT_VAR_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = CLIENT_VAR_RE.exec(src)) !== null) {
      const name = m[0];
      if (reportedByValue.has(name)) continue;
      if (PUBLIC_BY_DESIGN_RE.test(name)) continue;
      if (!SECRET_NAME_RE.test(name) && !SERVER_PROVIDER_RE.test(name)) continue;

      // If this file assigns the variable, judge the value too, so a
      // placeholder in .env.example reads as a naming problem rather than a
      // breach. Only a REAL-looking value gets called a leak.
      const assign = new RegExp(`${name}\\s*[:=]\\s*["']?([^"'\\n\\r]*)`).exec(src);
      const value = assign?.[1]?.trim() ?? null;
      const placeholder = value !== null && PLACEHOLDER_RE.test(value);

      // The NAME signal does not fire in test scaffolding at all -- the same
      // conclusion githubScan reached for generic_secret_assignment. Inside a
      // test, a server-only name proves only that somebody named a variable,
      // and the names here are usually inside an expected finding id
      // ("...:NEXT_PUBLIC_X_SECRET:.env") rather than a variable at all. A
      // real-looking VALUE in a test file still reports, through the value
      // signals above, which is where the evidence actually is.
      if (inTest) continue;

      push(
        `github:public_prefixed_secret:${name}:${file.path}`,
        placeholder ? "WARNING" : "CRITICAL",
        placeholder
          ? `Server-only secret name behind a public prefix: ${name} (${file.path})`
          : `Secret exposed to every browser: ${name} (${file.path})`,
        placeholder
          ? `${file.path} declares ${name}. The value here is a placeholder, so nothing has leaked yet — but the prefix means whatever gets filled in later is inlined into the JavaScript you serve to every visitor. Rename it without the public prefix now, while it's still free to do so, and read it server-side only.`
          : `${name} carries a public prefix, which inlines it into the browser bundle at build time — anyone can read it in devtools, and rotating the deployment doesn't help until the value itself is rotated. The name says this is a server-only secret. Rotate it, then move it to a variable with no public prefix and read it only in a server route or Server Component.`
      );
    }
  }

  return out;
}

/** Aggregate — one call for the run orchestrator. */
export function scanClientExposure(files: RepoFile[]): GithubFinding[] {
  return [...scanServerSecretsInClientCode(files), ...scanPublicPrefixedSecrets(files)];
}

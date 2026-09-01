import type { Severity } from "@/lib/types";

// PURE GitHub source-scan detectors — no network. All I/O (repo reads, OSV
// lookups) lives in lib/deep/github.ts; this module turns fetched content into
// deep_findings-shaped findings and is fully unit-testable with fixtures. Same
// stable-id + severity contract as lib/deep/envaudit.ts.

export interface GithubFinding {
  id: string; // stable diff key
  severity: Severity;
  title: string;
  consequence: string;
  packageName: string | null;
  version: string | null;
  vulnId: string | null;
  cveId: string | null;
}

export interface RepoFile {
  path: string;
  content: string;
}

export interface Dep {
  name: string;
  version: string;
}

// ── Committed secrets ──────────────────────────────────────────────────────
// Deliberately high-precision patterns (real leaked-credential shapes), so we
// don't cry wolf over every "password" string. Public NEXT_PUBLIC_* assignments
// are never flagged — they're meant to ship.
const SECRET_PATTERNS: { id: string; label: string; re: RegExp }[] = [
  { id: "private_key", label: "a PEM private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "supabase_service_key", label: "a Supabase service-role key", re: /\bsb_secret_[A-Za-z0-9_-]{10,}/ },
  { id: "aws_access_key", label: "an AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "openai_key", label: "an OpenAI API key", re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { id: "generic_secret_assignment", label: "a hardcoded secret", re: /(?<!NEXT_PUBLIC_)(SERVICE_ROLE_KEY|_SECRET|PRIVATE_KEY|PASSWORD)\s*[:=]\s*["'][^"'\s]{8,}["']/ },
];

// A committed dotenv file.
const COMMITTED_ENV_RE = /(^|\/)\.env(\.[A-Za-z0-9_-]+)*$/;

// ...except the ones every project is SUPPOSED to commit.
//
// `.env.example` and `.env.template` are the documented way to tell a new
// contributor which variables exist. Auditing a real Supabase starter reported
// its committed `.env.template` as a CRITICAL leak, which is both wrong and the
// most common file shape in this market: our own repository never caught it
// because it gitignores `.env*`, so the placeholder is never committed here.
//
// Their CONTENT is still scanned by the credential patterns below, so a real key
// pasted into `.env.example` is still reported. It is the file's existence that
// stops being a finding.
const ENV_PLACEHOLDER_RE = /\.(example|template|sample|dist|defaults?|placeholder|tpl)$/i;

/** Prefixes whose values are published to the browser on purpose. */
const PUBLIC_ENV_PREFIX = /^(NEXT_PUBLIC_|EXPO_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|GATSBY_)/;

/** A filled-in value rather than a fill-me-in marker. */
const ENV_FILLED_VALUE = /^["']?(?!\s*$)(?!your[-_])(?!<)(?!\.\.\.)(?!xxx)[^\s"']{16,}/i;

/**
 * Values that are long enough to look filled in but carry no secret.
 *
 * A DATABASE_URL pointing at localhost is the default every starter ships with,
 * and a pk_test_ / pk_live_ publishable key is published on purpose. Auditing a
 * 7,000-star boilerplate reported its committed .env as a credential leak on the
 * strength of `postgresql://postgres@localhost:5432/db`.
 */
const HARMLESS_ENV_VALUE =
  /^["']?(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|http|https):\/\/[^\s"']*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|@db[:\/]|@postgres[:\/]|@mysql[:\/]|host\.docker\.internal)/i;

/**
 * Keys whose NAME says they carry a credential.
 *
 * Without this, any long value counted. A 7,000-star boilerplate's committed
 * .env.production was reported CRITICAL because it sets CHECKLY_PROJECT_NAME
 * and a contact email address, neither of which is a secret by any reading.
 */
const CREDENTIAL_KEY_RE =
  /(SECRET|PASSWORD|PRIVATE_KEY|API_?KEY|_KEY$|TOKEN|CREDENTIAL|SERVICE_ROLE|DSN|CONNECTION_STRING|DATABASE_URL|AUTH)/i;

/** Vendor prefixes that mark a key as publishable. */
const PUBLISHABLE_KEY_VALUE = /^["']?(?:pk_(?:test|live)_|sb_publishable_|whsec_test_)/i;

/**
 * Whether a committed env file actually carries a secret.
 *
 * A file holding only NEXT_PUBLIC_/EXPO_PUBLIC_ values carries nothing private:
 * those ship to the browser by design, and the Supabase anon key is meant to be
 * there. A real Supabase starter committed exactly that and was reported as a
 * CRITICAL credential leak, which is the same overreach as flagging the
 * publishable key in a bundle, something this codebase already refuses to do.
 */
export function envFileHasSecret(content: string): boolean {
  for (const line of content.split("\n")) {
    const match = /^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (PUBLIC_ENV_PREFIX.test(key)) continue;
    if (!CREDENTIAL_KEY_RE.test(key)) continue;
    const value = rawValue.trim();
    if (HARMLESS_ENV_VALUE.test(value) || PUBLISHABLE_KEY_VALUE.test(value)) continue;
    if (ENV_FILLED_VALUE.test(value)) return true;
  }
  return false;
}

// ── Fixtures are not leaks ─────────────────────────────────────────────────
// A test suite that exercises a secret detector has to contain things shaped
// like secrets. Reporting those is how an audit produces fifteen criticals
// about a repository with nothing wrong with it, and one wrong critical costs
// more trust than five right ones earn.
//
// The rule is NOT "skip test files". Real credentials are committed in test
// files all the time -- a suite that talks to a live sandbox needs a real key.
// So the path decides how loudly we speak, and the VALUE decides whether we
// speak at all.
// Seed and fixture scripts populate a development database. Their passwords are
// dev logins by construction: a 7,000-star starter kit sets ADMIN_PASSWORD to
// 'admin@123' in prisma/seed.ts, and telling its author to rotate that is noise.
const SEED_PATH_RE = /(^|\/)(seeds?|fixtures?)\.[cm]?[jt]s$|(^|\/)(seeds?|fixtures?)\//i;

const TEST_PATH_RE =
  /(^|\/)(__tests__|__mocks__|__fixtures__|tests?|spec|fixtures|mocks|examples?)(\/)|\.(test|spec)\.[cm]?[jt]sx?$|\.fixture\.[cm]?[jt]sx?$|(^|\/)vitest\.config\.[cm]?[jt]s$|(^|\/)jest\.config\.[cm]?[jt]s$|(^|\/)jest\.setup\.[cm]?[jt]s$/i;

/** Whether this file is test scaffolding rather than shipped code. */
export function isTestPath(path: string): boolean {
  return TEST_PATH_RE.test(path) || SEED_PATH_RE.test(path);
}

// Values that announce themselves as fake. Vendors publish several of these
// verbatim in their own documentation -- AKIAIOSFODNN7EXAMPLE is Amazon's.
// Matched as substrings, not words: the marker is usually welded into the
// value itself. AKIAIOSFODNN7EXAMPLE and sb_secret_example_key both contain
// "example" with no word boundary anywhere near it, and a \b here silently
// matched neither -- which is the whole false-positive burst all over again.
const SYNTHETIC_RE =
  /(example|fake|dummy|placeholder|redacted|notreal|test[-_]?key|testkey|your[-_]\w+|changeme|xxxx|aaaa|00000|1234567|deadbeef|foobar|lorem)/i;

/**
 * Whether a matched credential looks manufactured for a test.
 *
 * Deliberately conservative: it judges the matched text and its immediate line,
 * not the file. A genuine key that happens to sit near the word "example" is
 * rare; a fixture that contains none of these markers still gets reported, just
 * more quietly.
 */
export function looksSynthetic(match: string, line: string): boolean {
  if (SYNTHETIC_RE.test(match) || SYNTHETIC_RE.test(line)) return true;
  // A `test-` or `test_` segment anywhere in the value: "test-service-role-key".
  if (/(^|["'`\s=:(,\-_])test[-_]/i.test(match) || /(^|["'`\s=:(,])test[-_]/i.test(line)) return true;
  // Nobody's real key spells the alphabet. abcdefgh and AbCdEfGh are the two
  // ways a person types a placeholder they do not want to think about.
  if (hasAlphabeticRun(match) || hasAlphabeticRun(line)) return true;
  // A PEM header with nothing under it, or a key body of one repeated
  // character, is a shape and not a key.
  if (/-----BEGIN/.test(match) && /-----BEGIN[^]{0,40}(-----END|["'`])/.test(line)) return true;
  const body = match.replace(/[^A-Za-z0-9]/g, "");
  if (body.length >= 8 && new Set(body.toLowerCase()).size <= 3) return true;
  return false;
}

/** Six or more consecutive letters in alphabetical order — abcdef, AbCdEf. */
function hasAlphabeticRun(text: string): boolean {
  const letters = text.toLowerCase().replace(/[^a-z]/g, "");
  let run = 1;
  for (let i = 1; i < letters.length; i++) {
    run = letters.charCodeAt(i) === letters.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run >= 6) return true;
  }
  return false;
}

/** Whether the match sits on a comment line. */
export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|\*|\/\*|#|--)/.test(line);
}

/** The line a match sits on, for judging it in context. */
function lineOf(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? undefined : end);
}

export function scanSecrets(files: RepoFile[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    if (COMMITTED_ENV_RE.test(file.path) && !ENV_PLACEHOLDER_RE.test(file.path)) {
      const id = `github:committed_env:${file.path}`;
      // A committed env file holding only placeholders is untidy, not urgent.
      // Reserving CRITICAL for a file that actually carries a value keeps the
      // severity meaning something.
      const hasRealValue = envFileHasSecret(file.content);
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id,
          severity: hasRealValue ? "CRITICAL" : "WARNING",
          title: `Environment file committed to the repo (${file.path})`,
          consequence: hasRealValue
            ? `${file.path} is committed to source control and contains values. Anyone with repository access, and anyone at all if it ever goes public, can read them. Remove the file, add it to .gitignore, and rotate every value in it.`
            : `${file.path} is committed to source control. Its values are either placeholders or public by design, such as a NEXT_PUBLIC_ variable or a Supabase anon key, so nothing private is exposed here. Add it to .gitignore before something real is pasted into it.`,
          packageName: null, version: null, vulnId: null, cveId: null,
        });
      }
    }

    // A placeholder env file is documentation of which variables exist. Its
    // values are examples by definition, so it gets the same treatment as test
    // scaffolding: the generic assignment pattern proves nothing there, and a
    // synthetic-looking value is a placeholder rather than a leak. A
    // real-looking vendor-shaped key pasted into one is still reported.
    const inTest = isTestPath(file.path) || ENV_PLACEHOLDER_RE.test(file.path);

    for (const pat of SECRET_PATTERNS) {
      const match = pat.re.exec(file.content);
      if (!match) continue;

      // A fixture value in a test file is scaffolding, not a leak. Both
      // conditions are required: a synthetic-looking value in real code is
      // still worth saying out loud, and a real-looking value in a test file
      // is still a committed credential.
      // The vendor-shaped patterns prove a real credential's SHAPE, so in a
      // test file they still get the value check. The generic assignment
      // pattern proves only that something was assigned to a name containing
      // "SECRET" — inside test scaffolding that is a fixture by construction,
      // and reporting it is how a detector's own suite becomes a finding.
      if (inTest && pat.id === "generic_secret_assignment") continue;

      const line = lineOf(file.content, match.index);

      // A placeholder written INTO a comment is documentation, not a
      // credential. This file proved it on itself: the comment explaining that
      // AKIAIOSFODNN7EXAMPLE is Amazon's published example contains the string,
      // and the scanner reported its own explanation as a leaked AWS key.
      // A real-looking key in a comment still reports — people do paste those.
      if (isCommentLine(line) && looksSynthetic(match[0], line)) continue;

      if (inTest && looksSynthetic(match[0], line)) continue;

      const id = `github:secret:${pat.id}:${file.path}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        severity: inTest ? "WARNING" : "CRITICAL",
        title: inTest
          ? `Possible ${pat.label} in test file ${file.path}`
          : `Possible ${pat.label} committed in ${file.path}`,
        consequence: inTest
          ? `${file.path} is test scaffolding, and the value in it does not look manufactured. If the suite authenticates against something real, that credential is in source control and should be rotated and moved to an environment variable the suite reads.`
          : `${file.path} appears to contain ${pat.label}. Committed credentials are compromised the moment they're pushed — rotate it now and move it to a server-only environment variable.`,
        packageName: null, version: null, vulnId: null, cveId: null,
      });
    }
  }
  return findings;
}

// ── Secrets / tokens logged ────────────────────────────────────────────────
// Logging a secret ships it to wherever logs go (Vercel, a log drain, a
// third-party) and retains it. High-precision: matches a log call that logs a
// SENSITIVE PROPERTY (obj.password / req.headers.authorization) or interpolates
// a sensitive variable — not the mere string "password" in a message.
const LOG_PROP_RE =
  /(console\.(log|error|warn|info|debug)|logger\.\w+)\s*\([^)]*\.(password|passwd|secret|token|access_?token|refresh_?token|api_?key|apiKey|authorization|cookie|private_?key|privateKey|service_?role|serviceRole)\b/i;
// Exclude LLM/usage token COUNTS (input_tokens/output_tokens/prompt_tokens…) —
// those are numbers, not auth secrets. Guard the bare "token" alternative.
// A COUNT of tokens is a number, not a credential. The snake_case exclusions
// were already here; `tokensIn` and `tokensOut` slipped through them, and our
// own token-efficiency log line was reported as a leaked secret. Plural, or
// followed by a counting word, means arithmetic.
const LOG_TEMPLATE_RE =
  /(console\.(log|error|warn|info|debug)|logger\.\w+)\s*\(\s*`[^`]*\$\{[^}]*((?<!input_)(?<!output_)(?<!prompt_)(?<!completion_)(?<!total_)(?<!num_)(?<!max_)token(?!s?(In|Out|Count|Used|Usage|Estimate|Budget|Limit)\b)(?!s\b)|secret|password|apikey|authorization|cookie|private_?key)[^}]*\}/i;

export function scanLoggedSecrets(files: RepoFile[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file.path)) continue;
    // A test that asserts a redactor works has to contain the unredacted call.
    // This finding is about what reaches a production log drain, and a test
    // file does not run in production.
    if (isTestPath(file.path)) continue;
    if (LOG_PROP_RE.test(file.content) || LOG_TEMPLATE_RE.test(file.content)) {
      findings.push({
        id: `github:logged_secret:${file.path}`,
        severity: "WARNING",
        title: `Sensitive value written to logs in ${file.path}`,
        consequence:
          `${file.path} appears to log a secret/token/credential. Logs are shipped and retained wherever your host or log drain sends them — anyone with log access then has the secret. Remove it or redact before logging.`,
        packageName: null, version: null, vulnId: null, cveId: null,
      });
    }
  }
  return findings;
}

// ── Token-storage anti-pattern ─────────────────────────────────────────────
// The default @supabase/supabase-js browser client keeps the session in
// localStorage, where any XSS can read it. The cookie-based @supabase/ssr
// client doesn't. If the project uses @supabase/ssr anywhere, assume it's on
// the safe path; otherwise, a createClient from supabase-js is worth flagging.
export function scanTokenStorage(files: RepoFile[]): GithubFinding[] {
  const usesSsr = files.some((f) => /@supabase\/ssr/.test(f.content));
  if (usesSsr) return [];

  const hit = files.find(
    (f) => /@supabase\/supabase-js/.test(f.content) && /\bcreateClient\s*\(/.test(f.content)
  );
  if (!hit) return [];

  return [
    {
      id: "github:token_storage:localstorage",
      severity: "WARNING",
      title: "Auth session stored in localStorage (XSS can steal it)",
      consequence:
        `This app uses the default @supabase/supabase-js client (e.g. in ${hit.path}), which stores the auth session in localStorage — any cross-site-scripting bug can read the token and hijack the session. Move to the cookie-based @supabase/ssr client so the token is out of JavaScript's reach.`,
      packageName: null, version: null, vulnId: null, cveId: null,
    },
  ];
}

// ── Dependencies ───────────────────────────────────────────────────────────
// Prefer the lockfile (exact, resolved versions — what OSV needs). Fall back to
// package.json ranges with the range operators stripped.
export function extractDependencies(packageJson: string, packageLock: string | null): Dep[] {
  const deps = new Map<string, string>();

  if (packageLock) {
    try {
      const lock = JSON.parse(packageLock) as {
        packages?: Record<string, { version?: string }>;
        dependencies?: Record<string, { version?: string }>;
      };
      // npm lockfile v2/v3: keys like "node_modules/<name>" and nested
      // "node_modules/a/node_modules/<name>" — take the segment after the LAST
      // "node_modules/" so nested deps resolve to their real package name.
      for (const [key, val] of Object.entries(lock.packages ?? {})) {
        const idx = key.lastIndexOf("node_modules/");
        const name = idx >= 0 ? key.slice(idx + "node_modules/".length) : key;
        if (name && val?.version) deps.set(name, val.version);
      }
      // v1 fallback
      for (const [name, val] of Object.entries(lock.dependencies ?? {})) {
        if (val?.version && !deps.has(name)) deps.set(name, val.version);
      }
    } catch {
      /* fall through to package.json */
    }
  }

  if (deps.size === 0) {
    try {
      const pkg = JSON.parse(packageJson) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      for (const block of [pkg.dependencies, pkg.devDependencies]) {
        for (const [name, range] of Object.entries(block ?? {})) {
          const clean = range.replace(/^[\^~>=<\s]+/, "").trim();
          if (clean && /^\d/.test(clean)) deps.set(name, clean);
        }
      }
    } catch {
      /* no parseable deps */
    }
  }

  return [...deps].map(([name, version]) => ({ name, version }));
}

// OSV vuln for a package, as returned by lib/deep/github.ts's queryOsv.
export interface OsvVuln {
  id: string; // OSV id, e.g. GHSA-xxxx
  cveId: string | null;
  summary: string;
  severity: Severity;
  // Smallest version that resolves this vuln (from OSV `affected` ranges), or
  // null if OSV didn't publish a fixed version — drives the auto-fix PR.
  fixedVersion: string | null;
}

// Pure: turn resolved (dep -> vulns) results into findings.
export function depFindings(results: { dep: Dep; vulns: OsvVuln[] }[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const { dep, vulns } of results) {
    for (const v of vulns) {
      findings.push({
        id: `github:dep:${dep.name}:${v.id}`,
        severity: v.severity,
        title: `${dep.name}@${dep.version} — ${v.cveId ?? v.id}`,
        consequence: `${v.summary} Update ${dep.name} past the vulnerable version.`,
        packageName: dep.name,
        version: dep.version,
        vulnId: v.id,
        cveId: v.cveId,
      });
    }
  }
  return findings;
}

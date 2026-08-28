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

// A committed dotenv file is its own red flag regardless of contents.
const COMMITTED_ENV_RE = /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/;

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
const TEST_PATH_RE =
  /(^|\/)(__tests__|__mocks__|__fixtures__|tests?|spec|fixtures|mocks|examples?)(\/)|\.(test|spec)\.[cm]?[jt]sx?$|\.fixture\.[cm]?[jt]sx?$|(^|\/)vitest\.config\.[cm]?[jt]s$|(^|\/)jest\.config\.[cm]?[jt]s$|(^|\/)jest\.setup\.[cm]?[jt]s$/i;

/** Whether this file is test scaffolding rather than shipped code. */
export function isTestPath(path: string): boolean {
  return TEST_PATH_RE.test(path);
}

// Values that announce themselves as fake. Vendors publish several of these
// verbatim in their own documentation -- AKIAIOSFODNN7EXAMPLE is Amazon's.
// Matched as substrings, not words: the marker is usually welded into the
// value itself. AKIAIOSFODNN7EXAMPLE and sb_secret_example_key both contain
// "example" with no word boundary anywhere near it, and a \b here silently
// matched neither -- which is the whole false-positive burst all over again.
const SYNTHETIC_RE =
  /(example|fake|dummy|placeholder|redacted|notreal|test[-_]?key|testkey|your[-_](key|token|secret)|changeme|xxxx|aaaa|00000|1234567|deadbeef|foobar|lorem)/i;

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
function isCommentLine(line: string): boolean {
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
    if (COMMITTED_ENV_RE.test(file.path)) {
      const id = `github:committed_env:${file.path}`;
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id,
          severity: "CRITICAL",
          title: `Environment file committed to the repo (${file.path})`,
          consequence:
            `${file.path} is committed to source control — anyone with repo access (and anyone if it's ever public) can read whatever secrets it holds. Remove it, add it to .gitignore, and rotate every value in it.`,
          packageName: null, version: null, vulnId: null, cveId: null,
        });
      }
    }

    const inTest = isTestPath(file.path);

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

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

    for (const pat of SECRET_PATTERNS) {
      if (pat.re.test(file.content)) {
        const id = `github:secret:${pat.id}:${file.path}`;
        if (seen.has(id)) continue;
        seen.add(id);
        findings.push({
          id,
          severity: "CRITICAL",
          title: `Possible ${pat.label} committed in ${file.path}`,
          consequence:
            `${file.path} appears to contain ${pat.label}. Committed credentials are compromised the moment they're pushed — rotate it now and move it to a server-only environment variable.`,
          packageName: null, version: null, vulnId: null, cveId: null,
        });
      }
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
const LOG_TEMPLATE_RE =
  /(console\.(log|error|warn|info|debug)|logger\.\w+)\s*\(\s*`[^`]*\$\{[^}]*((?<!input_)(?<!output_)(?<!prompt_)(?<!completion_)(?<!total_)(?<!num_)(?<!max_)token|secret|password|apikey|authorization|cookie|private_?key)[^}]*\}/i;

export function scanLoggedSecrets(files: RepoFile[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file.path)) continue;
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

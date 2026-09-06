import { isTestPath, isScaffoldPath, type GithubFinding, type RepoFile } from "./githubScan";

// Tier-1 gap-closers (CLAUDE.md 🟡 rows): cheap, high-precision source
// patterns that close crypto / client-side / URL-exposure gaps the config scan
// can't see. PURE — no network. Rides the GitHub source layer. Same FP/FN
// discipline as githubScan.ts: only KNOWN-BAD, context-guarded patterns, so we
// don't cry wolf. Every finding uses the shared GithubFinding shape.

const CODE_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const f = (
  id: string, severity: GithubFinding["severity"], title: string, consequence: string
): GithubFinding => ({ id, severity, title, consequence, packageName: null, version: null, vulnId: null, cveId: null });

// ── Weak crypto ────────────────────────────────────────────────────────────
// md5/sha1 are broken for password hashing (fast + collision-prone); only flag
// when the file is actually about passwords/credentials so md5 cache keys /
// etags don't false-positive. Math.random() is not cryptographically secure —
// flag only when its result feeds a security value (token/secret/otp/nonce).
const WEAK_HASH_RE = /createHash\(\s*["'](md5|sha1)["']\s*\)/i;
const PASSWORD_CONTEXT_RE = /\b(password|passwd|pwd|credential|bcrypt|hashPassword)\b/i;
const INSECURE_RANDOM_RE =
  /\b(token|secret|otp|nonce|apikey|api_?key|session_?id|reset_?token|password|salt)\w*\s*[:=][^;\n]*Math\.random\s*\(/i;

export function scanWeakCrypto(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;
    if (WEAK_HASH_RE.test(file.content) && PASSWORD_CONTEXT_RE.test(file.content)) {
      out.push(f(`github:weak_hash:${file.path}`, "WARNING",
        `Weak hash (md5/sha1) used in a password context in ${file.path}`,
        `${file.path} hashes with md5/sha1 near password/credential code. These are fast and broken for passwords — a leaked table is trivially cracked. Use bcrypt/scrypt/argon2 (or let Supabase Auth handle passwords).`));
    }
    if (INSECURE_RANDOM_RE.test(file.content)) {
      out.push(f(`github:insecure_random:${file.path}`, "WARNING",
        `Security token generated with Math.random() in ${file.path}`,
        `${file.path} builds a token/secret/OTP from Math.random(), which is predictable — an attacker can guess valid values. Use crypto.randomUUID() or crypto.getRandomValues() / node:crypto randomBytes.`));
    }
  }
  return out;
}

// ── Client-side XSS sinks ──────────────────────────────────────────────────
// The dominant frontend runtime gap the config scan can't reach. High-precision
// sink patterns; each is a genuine "user input here = XSS" vector.
const XSS_SINKS: { id: string; label: string; re: RegExp; fix: string }[] = [
  { id: "dangerously_set_html", label: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/,
    fix: "Only pass HTML you've sanitized (e.g. DOMPurify); never render user-supplied or fetched HTML raw." },
  { id: "inner_html_assign", label: "an innerHTML/outerHTML assignment", re: /\.(inner|outer)HTML\s*=/,
    fix: "Set textContent instead, or sanitize the HTML before assigning." },
  { id: "eval_call", label: "eval()/new Function()", re: /\beval\s*\(|new\s+Function\s*\(/,
    fix: "Remove eval/new Function; parse data with JSON.parse and dispatch on values instead of executing strings." },
  { id: "postmessage_wildcard", label: "postMessage to '*'", re: /postMessage\s*\([^,]+,\s*["']\*["']/,
    fix: "Pass an explicit target origin to postMessage, and validate event.origin on the receiver." },
];

export function scanClientXss(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;
    for (const sink of XSS_SINKS) {
      if (!sink.re.test(file.content)) continue;
      const id = `github:xss_sink:${sink.id}:${file.path}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(f(id, "WARNING",
        `Client-side XSS sink (${sink.label}) in ${file.path}`,
        `${file.path} uses ${sink.label}. If any user-controlled or fetched value reaches it, an attacker can run script in your users' browsers (session theft, account takeover). ${sink.fix}`));
    }
  }
  return out;
}

// ── Sensitive data in URLs ─────────────────────────────────────────────────
// Tokens/passwords in query strings leak into logs, browser history, and
// Referer headers. Two-signal to avoid flagging prose: a SENSITIVE query param
// AND a URL-ish context (a URL literal, a fetch/redirect/href call, or a quoted
// path). A benign `?q=…&page=2` has no sensitive param, so it stays silent.
const SENSITIVE_QUERY_RE =
  /[?&](access_?token|auth_?token|api_?key|apikey|password|passwd|secret|session_?id)=/i;
const URLISH_RE = /(https?:\/\/|fetch\s*\(|redirect\s*\(|\.href\s*=|new URL\(|["'`]\/)/;

export function scanSecretsInUrl(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;
    if (SENSITIVE_QUERY_RE.test(file.content) && URLISH_RE.test(file.content)) {
      out.push(f(`github:secret_in_url:${file.path}`, "WARNING",
        `Sensitive value passed in a URL query string in ${file.path}`,
        `${file.path} puts a token/password/secret in a URL query string. URLs are logged by servers/proxies, saved in browser history, and leak via the Referer header. Send it in a request body or header over HTTPS instead.`));
    }
  }
  return out;
}

// ── Injection sinks (SQLi / command / path / open-redirect) ────────────────
// The biggest Strix-class category we can catch statically. High precision:
// every pattern requires evidence of DYNAMIC input (a `${...}` interpolation,
// `+` concatenation, or a request field), so fully-static strings never fire.
type Sev = GithubFinding["severity"];
const INJECTION_CHECKS: { id: string; label: string; severity: Sev; res: RegExp[]; fix: string }[] = [
  {
    id: "sql_injection", label: "SQL injection", severity: "CRITICAL",
    // A SQL KEYWORD IS NOT EVIDENCE. It has to sit in a place where SQL is
    // executed. The previous first pattern matched any template literal holding
    // a standalone keyword plus any interpolation, so `user-select: none;` in a
    // styled-components block, "Can't update nested record ${x}" in an error,
    // and "paths were updated successfully ${n}" in a console line all read as
    // SQL injection. Measured 2026-09-06 over full archives: 155 of 178
    // criticals on seven new repositories, and 172 on the five corpora this
    // detector was supposedly validated against.
    //
    // Shapes counted across all twelve repositories before choosing these three
    // (files matching): explicit unsafe API 30, execution call + template
    // carrying a keyword and an interpolation 76, execution call + quoted
    // concatenation 6. Dropping the keyword requirement from the second raises
    // it to 186, so the keyword stays. Nothing is included that had no
    // occurrences to exercise it.
    //
    // NOT matched, deliberately: a TAGGED template on a raw-SQL tag --
    // prisma.$queryRaw`… ${id}` and postgres.js sql`… ${id}` bind their
    // interpolations as parameters, so they are safe by construction and 131
    // files use them. Flagging those was a correctness error, not just noise.
    res: [
      // The APIs whose entire purpose is to bypass parameterisation.
      /(?:\$(?:query|execute)RawUnsafe|\bsql\s*\.\s*unsafe)\s*\(\s*[^)]*(?:\$\{|\+)/,
      // SQL built by interpolation inside an execution call.
      /(?:\.\s*(?:query|execute|raw)|sequelize\.query|knex\.raw)\s*\(\s*`[^`]*\b(?:select|insert|update|delete|where|from|drop\s+table|union\s+select)\b[^`]*\$\{/i,
      // SQL built by concatenation inside an execution call.
      /(?:\.\s*(?:query|execute|raw)|sequelize\.query|knex\.raw)\s*\(\s*['"][^'"]*\b(?:select|insert|update|delete|where|from)\b[^)]*\+/i,
    ],
    fix: "Never build SQL by concatenating or interpolating input. Use parameterized queries / bound parameters (e.g. $1 placeholders), or your ORM's safe query builder.",
  },
  {
    id: "command_injection", label: "OS command injection", severity: "CRITICAL",
    res: [
      /\b(exec|execSync|execFile|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/,
      /\b(exec|execSync|execFile|spawn|spawnSync)\s*\(\s*['"][^'"]*['"]\s*\+/,
    ],
    fix: "Don't pass interpolated/concatenated input to a shell. Use the array-args form of execFile/spawn (no shell), and validate against an allow-list.",
  },
  {
    id: "path_traversal", label: "path traversal", severity: "WARNING",
    res: [
      /\b(readFile|readFileSync|createReadStream|sendFile|writeFile|writeFileSync|unlink)\s*\([^)]*(req\.(query|params|body)|searchParams|nextUrl)/i,
    ],
    fix: "Resolve the final path and confirm it stays inside the intended directory (path.resolve + prefix check), or map input to an allow-list of files — never feed request input straight into a file path.",
  },
  {
    id: "open_redirect", label: "open redirect", severity: "WARNING",
    res: [
      /\b(redirect|res\.redirect|NextResponse\.redirect)\s*\(\s*[^)]*(req\.(query|params|body)|searchParams\.get|nextUrl\.searchParams)/i,
    ],
    fix: "Validate the redirect target against an allow-list of your own paths/hosts before redirecting — never redirect to a raw user-supplied URL.",
  },
];

export function scanInjection(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;
    for (const check of INJECTION_CHECKS) {
      if (!check.res.some((re) => re.test(file.content))) continue;
      // THE PATH DECIDES HOW LOUDLY. Same rule the secret scanner has applied
      // since August, applied here for the first time: injection evidence in
      // test scaffolding or a build script is reported one step quieter, and
      // never dropped. The trade is that a genuine injection in a file under
      // test/ or scripts/ arrives as a WARNING rather than a CRITICAL; the
      // mitigation is that it still arrives, with the same text.
      const quiet = isTestPath(file.path) || isScaffoldPath(file.path);
      const severity: Sev = quiet && check.severity === "CRITICAL" ? "WARNING" : check.severity;
      out.push(f(`github:injection:${check.id}:${file.path}`, severity,
        `Possible ${check.label} in ${file.path}`,
        `${file.path} appears to build a ${check.label === "path traversal" ? "file path" : check.label === "open redirect" ? "redirect" : "command"} from untrusted input. ${check.fix}`));
    }
  }
  return out;
}

// Aggregate — one call for the run orchestrator.
export function scanCodePatterns(files: RepoFile[]): GithubFinding[] {
  return [...scanWeakCrypto(files), ...scanClientXss(files), ...scanSecretsInUrl(files), ...scanInjection(files)];
}

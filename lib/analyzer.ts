import Anthropic from "@anthropic-ai/sdk";
import type { ScanResult } from "./scanner";
import { shiplockFundedCallAllowed } from "@/lib/funding";

// ── Result types ──────────────────────────────────────────────────────────────

export interface CodeFix {
  file:        string;
  description: string;
  prompt:      string;
}

export interface AnalysisIssue {
  severity:    "CRITICAL" | "WARNING" | "INFO";
  title:       string;
  consequence: string;
  fix:         string;
  codefix?:    CodeFix;
}

export interface AnalysisResult {
  issues: AnalysisIssue[];
  summary: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a Supabase security auditor writing for non-technical startup founders.

You will receive a JSON scan result covering 16 security checks. Analyse every
check and return specific, actionable issues. There is NO letter grade — never
invent one. Lead with the truth: what's open, what it costs, how to fix it.

═══════════════════════════════════════════════════════════
CHECK 1 — RLS STATUS  (tables[].rlsEnabled)
═══════════════════════════════════════════════════════════
Each table has rlsEnabled, policiesRetrieved, and policies fields.

• rlsEnabled: false
  → CRITICAL. The table is fully exposed — anyone with the anon key can read all rows.
  → Any exposed table is a CRITICAL finding.

• rlsEnabled: true + policiesRetrieved: true + policies.length > 0
  → GOOD. RLS is on and policies are confirmed. No issue needed.

• rlsEnabled: true + policiesRetrieved: true + policies.length === 0
  → WARNING. RLS is on (data not exposed) but no policies found. The app itself
    may be locked out. Suggest adding service-role and user-scoped policies.

• rlsEnabled: true + policiesRetrieved: false
  → GOOD (treat as correctly secured). pg_policies was unreadable — empty
    policies array does NOT mean no policies exist. Data is not publicly
    accessible. This is expected and fine — do NOT penalise it.

═══════════════════════════════════════════════════════════
CHECK 2 — KEY TYPE  (keyAnalysis)
═══════════════════════════════════════════════════════════
keyAnalysis fields: role, isServiceRole, jwtValid, projectRef, keyFormat
keyFormat is "jwt" (legacy anon/service_role JWT), "publishable" (current
sb_publishable_... anon-equivalent), or "secret" (current sb_secret_...
service_role-equivalent) — both key models are in real use, treat them
identically by isServiceRole, not by keyFormat.

• isServiceRole: true (keyFormat "jwt" with role "service_role", OR
  keyFormat "secret")
  → CRITICAL. The user submitted their master key — service_role JWT or
    sb_secret_... — to a public scanner. This key bypasses ALL RLS, can
    read/write everything, and must never leave the server.
  → Fix: rotate the key immediately in the Supabase dashboard, and use
    only the anon/publishable key for client-side operations.

• isServiceRole: false, keyFormat "jwt", role: "anon" — OR keyFormat
  "publishable"
  → GOOD. Correct key type for scanning, either key model.

• jwtValid: false
  → WARNING. The provided key could not be parsed at all (not a valid JWT,
    and not a recognized sb_publishable_/sb_secret_ prefix). Verify the
    key is copied correctly from the Supabase dashboard.

═══════════════════════════════════════════════════════════
CHECK 3 — RATE LIMITING  (rateLimiting)
═══════════════════════════════════════════════════════════
rateLimiting fields: tested, endpoint, requests, successes, rateLimited

• rateLimited: false AND successes >= 8
  → WARNING. All 10 rapid requests succeeded — no rate limiting detected on
    the REST API. Attackers can enumerate data at high speed.
    Recommend adding rate limiting via Supabase Edge Functions or a proxy.

• rateLimited: true → GOOD. No issue needed.
• tested: false → INFO. Could not be tested (no endpoints discovered).

═══════════════════════════════════════════════════════════
CHECK 4 — UNAUTHENTICATED ACCESS  (unauthAccess)
═══════════════════════════════════════════════════════════
unauthAccess fields: tested, results[]  (tableName, accessible, rowCount)

• Any result with accessible: true
  → CRITICAL. The table can be read with zero authentication — not even the
    anon key is required.
  → Fix: enable RLS and enforce JWT authentication on the Supabase API gateway.

• All results accessible: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 5 — SLOP SQUATTING  (slopSquatting)
═══════════════════════════════════════════════════════════
slopSquatting fields: tested, packageJsonAccessible, suspiciousPackages[]
Each package has: name, reason ("NOT_FOUND"|"VERY_NEW"), createdAt?

• packageJsonAccessible: false → No finding needed.

• reason "NOT_FOUND"
  → CRITICAL. AI tools sometimes invent package names. Attackers register
    these with malicious code. Fix: remove or replace each non-existent package.

• reason "VERY_NEW"
  → WARNING. Package created < 30 days ago. Higher supply-chain risk.
    Fix: verify the package's provenance before trusting it.

═══════════════════════════════════════════════════════════
CHECK 6 — MASS ASSIGNMENT  (massAssignment)
═══════════════════════════════════════════════════════════
massAssignment fields: tested, results[]  (tableName, vulnerable)

• ShipLock no longer sends this write probe to production, so it now always
  arrives as tested: false. Treat it like any other untested check.
• Any result with vulnerable: true (older scans only)
  → CRITICAL. The API accepted a PATCH containing privileged fields
    (is_paid, is_admin, role). An attacker could escalate their own privileges.
    Fix: use column-level security in RLS policies, or add a trigger that
    strips privileged fields from client updates.

• All vulnerable: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 7 — AUTH SECURITY  (authSecurity)
═══════════════════════════════════════════════════════════
authSecurity fields: tested, adminEndpointBlocked

• adminEndpointBlocked: false
  → CRITICAL. The auth admin endpoint (/auth/v1/admin/users) responded with
    a success status using only the anon key. This endpoint lists all users
    and should require the service_role key.
    Fix: verify your Supabase Auth configuration and ensure the anon key has
    no admin permissions.

• adminEndpointBlocked: true → GOOD.

═══════════════════════════════════════════════════════════
CHECK 8 — IDOR  (idor)
═══════════════════════════════════════════════════════════
idor fields: tested, results[]  (tableName, rowsAccessible)

• Any result with rowsAccessible: true
  → CRITICAL. A user-sensitive table (profiles, users, accounts, etc.) returned
    rows when accessed with only an anonymous API key and no user context.
    This means anyone can read other users' data without being authenticated.
    Fix: add RLS policies using auth.uid() = user_id to restrict each user
    to their own rows only.

• All rowsAccessible: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 9 — SECRETS EXPOSURE  (secretsExposure)
═══════════════════════════════════════════════════════════
secretsExposure fields: tested, exposedFiles[]

• exposedFiles[] has entries
  → CRITICAL. An environment file (e.g. .env, .env.local) is publicly
    reachable at the project URL and contains what appear to be API keys or
    secrets. This exposes your entire backend to attackers.
    Fix: remove all .env files from your public server root immediately and
    rotate every exposed key.

• exposedFiles[] empty → GOOD.

═══════════════════════════════════════════════════════════
CHECK 10 — SECURE AUTHENTICATION  (secureAuth)
═══════════════════════════════════════════════════════════
secureAuth fields: tested, loginRateLimited

• loginRateLimited: false
  → WARNING. Rapid login attempts to /auth/v1/token were not rate limited.
    An attacker can brute-force passwords at high speed.
    Fix: enable auth rate limiting in Supabase Auth settings or add a
    reverse proxy with rate limiting in front of the auth endpoint.

• loginRateLimited: true → No issue needed.

═══════════════════════════════════════════════════════════
CHECK 11 — HTTPS ENFORCEMENT  (httpsCheck)
═══════════════════════════════════════════════════════════
httpsCheck fields: tested, enforced

• enforced: false
  → CRITICAL. The project URL is not using HTTPS. All traffic is transmitted
    in plaintext, including API keys and user data.
    Fix: configure your hosting provider to enforce HTTPS.

• enforced: true → GOOD.

═══════════════════════════════════════════════════════════
CHECK 12 — BOT PROTECTION  (botProtection)
═══════════════════════════════════════════════════════════
botProtection fields: tested, rateLimitHeadersPresent

• rateLimitHeadersPresent: false
  → WARNING. API responses do not include rate-limit headers
    (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After).
    Without these headers, clients cannot self-throttle and bots can
    hammer the endpoint undetected.
    Fix: add rate limiting headers via Supabase Edge Functions or a CDN layer.

• rateLimitHeadersPresent: true → No issue needed.

═══════════════════════════════════════════════════════════
CHECK 13 — INPUT VALIDATION  (inputValidation)
═══════════════════════════════════════════════════════════
inputValidation fields: tested, sqlErrorExposed

• sqlErrorExposed: true
  → INFO (platform note, NOT critical). This tests the Supabase/PostgREST
    API, which returns detailed Postgres error messages (column names, types)
    BY DEFAULT — this is standard platform behavior, not a flaw the founder
    introduced, and it is NOT evidence of SQL injection (PostgREST
    parameterizes queries). RLS, not error opacity, is the real boundary.
    Honest framing: "Your Supabase API returns detailed database errors by
    default. This reveals column names to anyone who already has your public
    key — low risk on its own, and normal for this stack. Optional hardening,
    not a hole." Do NOT inflate its severity. Do NOT imply injection.

• sqlErrorExposed: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 14 — CORS CONFIGURATION  (corsConfig)
═══════════════════════════════════════════════════════════
corsConfig fields: tested, wildcardOrigin, allowOriginValue

• wildcardOrigin: true  (allowOriginValue === "*")
  → INFO (platform note, NOT critical). This tests the Supabase API gateway,
    which returns Access-Control-Allow-Origin: * BY DEFAULT for every project.
    Crucially, Supabase authenticates by a BEARER TOKEN in the Authorization
    header, NOT a cookie — so a wildcard origin is NOT the cross-site request
    (CSRF) risk it would be for a cookie-based app: a malicious site cannot
    make the browser attach the user's token. Honest framing: "Supabase's API
    allows any origin — its default. Because it uses header-based bearer auth,
    not cookies, this isn't the CSRF risk it looks like. No action needed here."
    Do NOT inflate its severity. Do NOT claim a logged-in user can be
    tricked into authenticated requests — that's false for this auth model.

• wildcardOrigin: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 15 — STACK TRACE EXPOSURE  (stackTraceCheck)
═══════════════════════════════════════════════════════════
stackTraceCheck fields: tested, exposed

• exposed: true
  → WARNING. A malformed request returned an error containing internal stack
    trace information (file paths, line numbers, or "Error:" strings).
    Fix: configure your error handler to return only generic error messages
    in production, and log detailed errors server-side only.

• exposed: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 16 — PUBLIC STORAGE BUCKETS  (publicBuckets)
═══════════════════════════════════════════════════════════
publicBuckets fields: tested, publicBuckets[] (bucket names),
suspiciousFiles[] ({bucket, file} — secret-looking filenames found at the
root of a public bucket: .env, credentials.json, id_rsa, .pem, etc.)

• publicBuckets[] has entries
  → CRITICAL. One or more Supabase Storage buckets are configured with
    public: true — anyone with the anon key can list and download every
    file in that bucket without authentication. This is the exact pattern
    behind real large-scale incidents in Lovable/Supabase apps.
    Fix: in the Supabase dashboard, open Storage → the bucket → toggle off
    "Public bucket," then add a storage RLS policy scoping access to the
    owning user.

• suspiciousFiles[] additionally has entries
  → Same CRITICAL finding, but be specific in the consequence text: name
    the exact file(s) found (e.g. ".env" in bucket "uploads") rather than
    only saying the bucket is public — this is no longer a theoretical
    risk, a secret-looking file is sitting there right now.

• publicBuckets[] empty → GOOD.

═══════════════════════════════════════════════════════════
CODEFIX FIELD (required for every issue)
═══════════════════════════════════════════════════════════
For every issue you generate, include a "codefix" object:
{
  "file":        "exact file path the user should open, e.g. supabase/migrations/fix.sql or next.config.mjs",
  "description": "one sentence describing what to change",
  "prompt":      "complete, ready-to-paste prompt for Claude Code or Supabase SQL Editor"
}

Rules for the prompt field:
• For SQL-fixable issues (RLS, policies, grants): start with
  "Run this SQL in your Supabase SQL Editor:" then include the exact SQL.
• For code-fixable issues (CORS, HTTPS, middleware, env vars): write a
  complete Claude Code prompt the user can paste into their own Claude chat,
  e.g. "In my Next.js app in middleware.ts, add rate limiting... Here is my
  current middleware.ts: [paste file contents]"
• Always use concrete file paths and exact SQL/code — never use placeholders
  like YOUR_TABLE_NAME without explaining how to substitute them.
• Keep prompts under 300 characters — they're meant to be copied verbatim.

═══════════════════════════════════════════════════════════
OUTPUT RULES
═══════════════════════════════════════════════════════════
• Plain English — no jargon, no CVE numbers, NO letter grade
• One sentence title; real-world consequence; exact SQL or config fix
• tested: false means the check did not run or its target could not be read.
  It is never a pass and never GOOD. Do not raise one issue per untested
  check; raise a single INFO issue titled "N checks could not be verified"
  that names them, and never describe them as safe
• Do not raise issues for checks that passed
• The summary is one honest sentence about what's open (e.g. "One critical issue
  and two warnings" or "Everything held") — never a grade. Say "Everything
  held" only when every check was tested
• Return ONLY valid JSON:
{
  "issues": [{
    "severity": "CRITICAL"|"WARNING"|"INFO",
    "title": string,
    "consequence": string,
    "fix": string,
    "codefix": {
      "file": string,
      "description": string,
      "prompt": string
    }
  }],
  "summary": string
}`;

const VALID_SEVERITIES = new Set(["CRITICAL", "WARNING", "INFO"]);
const TIMEOUT_MS = 30_000;

// ── Fallback issues from raw check results (used when Claude API is unavailable) ─

function countWarnings(scan: ScanResult): number {
  let count = 0;
  if (scan.rateLimiting?.rateLimited === false && (scan.rateLimiting?.successes ?? 0) >= 8) count++;
  if (scan.botProtection?.tested && scan.botProtection.rateLimitHeadersPresent === false) count++;
  if (scan.stackTraceCheck?.exposed) count++;
  if (scan.secureAuth?.tested && scan.secureAuth.loginRateLimited === false) count++;
  if (scan.slopSquatting?.suspiciousPackages?.some(p => (p as { reason?: string }).reason === "VERY_NEW")) count++;
  return count;
}

function buildFallback(scan: ScanResult): AnalysisResult {
  const criticals = estimateCriticalCount(scan);
  const warnings  = countWarnings(scan);

  const issues: AnalysisIssue[] = [];

  if (scan.keyAnalysis?.isServiceRole) {
    issues.push({
      severity:    "CRITICAL",
      title:       "Service role key submitted to a public scanner",
      consequence: "Your master key bypasses all RLS and can read or modify every table. Rotate it immediately.",
      fix:         "Go to Supabase → Project Settings → API → Rotate service_role key. Use only the anon key for client-side scans.",
    });
  }
  if (scan.tables.some(t => !t.rlsEnabled)) {
    const exposed = scan.tables.filter(t => !t.rlsEnabled).map(t => t.name).join(", ");
    issues.push({
      severity:    "CRITICAL",
      title:       "Tables exposed without Row Level Security",
      consequence: `Any user with the anon key can read all rows from: ${exposed}.`,
      fix:         `Run in Supabase SQL Editor:\n${scan.tables.filter(t => !t.rlsEnabled).map(t => `ALTER TABLE ${t.name} ENABLE ROW LEVEL SECURITY;`).join("\n")}`,
    });
  }
  if (scan.unauthAccess?.results?.some(r => r.accessible)) {
    issues.push({
      severity:    "CRITICAL",
      title:       "Tables readable without any authentication",
      consequence: "Unauthenticated requests (no API key at all) can read your data.",
      fix:         "Enable RLS on all tables and require JWT authentication via Supabase Auth.",
    });
  }
  if (scan.massAssignment?.results?.some(r => r.vulnerable)) {
    issues.push({
      severity:    "CRITICAL",
      title:       "Mass assignment allows privilege escalation",
      consequence: "An attacker can set is_paid or is_admin to true on their own account.",
      fix:         "Add RLS column-level restrictions or a trigger that strips privileged fields from client updates.",
    });
  }
  if (scan.authSecurity?.adminEndpointBlocked === false) {
    issues.push({
      severity:    "CRITICAL",
      title:       "Auth admin endpoint accessible with anon key",
      consequence: "The /auth/v1/admin/users endpoint is reachable without the service_role key, exposing your full user list.",
      fix:         "Check your Supabase Auth configuration and ensure the anon key has no admin permissions.",
    });
  }
  if (scan.idor?.results?.some(r => r.rowsAccessible)) {
    issues.push({
      severity:    "CRITICAL",
      title:       "User data accessible without authentication (IDOR)",
      consequence: "Sensitive user rows can be read with only the anon key and no user session.",
      fix:         "Add RLS policies: CREATE POLICY user_isolation ON profiles FOR ALL USING (auth.uid() = user_id);",
    });
  }
  if ((scan.secretsExposure?.exposedFiles?.length ?? 0) > 0) {
    issues.push({
      severity:    "CRITICAL",
      title:       "Environment file publicly accessible",
      consequence: `Secret files are reachable at your project URL: ${scan.secretsExposure!.exposedFiles.join(", ")}`,
      fix:         "Remove all .env files from your public server root immediately and rotate every exposed key.",
    });
  }
  if (scan.httpsCheck?.enforced === false) {
    issues.push({
      severity:    "CRITICAL",
      title:       "HTTPS not enforced",
      consequence: "All traffic including API keys and user data is transmitted in plaintext.",
      fix:         "Configure your hosting provider to redirect HTTP to HTTPS and set the HSTS header.",
    });
  }
  if (scan.inputValidation?.sqlErrorExposed) {
    issues.push({
      severity:    "INFO",
      title:       "Supabase returns detailed database errors (platform default)",
      consequence: "Your Supabase API returns detailed Postgres error messages by default, which reveal column names to anyone who already has your public key. This is standard for this stack and low risk — not SQL injection. Optional hardening, not a hole.",
      fix:         "Optional: reduce PostgREST error verbosity in your Supabase project settings. Not required — RLS, not error opacity, is your real boundary.",
    });
  }
  if (scan.corsConfig?.wildcardOrigin) {
    issues.push({
      severity:    "INFO",
      title:       "Supabase API allows any origin (platform default)",
      consequence: "Supabase's API gateway returns Access-Control-Allow-Origin: * for every project. Because Supabase authenticates by a bearer token in the header — not a cookie — a wildcard origin is not the cross-site (CSRF) risk it would be for a cookie-based app. No action needed.",
      fix:         "No action needed for the Supabase API itself. If your own app relays this API using cookie-based sessions, restrict CORS there.",
    });
  }
  if ((scan.publicBuckets?.publicBuckets?.length ?? 0) > 0) {
    const buckets = scan.publicBuckets!.publicBuckets.join(", ");
    const suspicious = scan.publicBuckets!.suspiciousFiles ?? [];
    const consequence = suspicious.length > 0
      ? `Secret-looking files are sitting in a public bucket right now: ${suspicious.map((s) => `"${s.file}" in "${s.bucket}"`).join(", ")}. Anyone with the anon key can download them without authentication.`
      : `Anyone with the anon key can list and download files from: ${buckets}, without authentication.`;
    issues.push({
      severity:    "CRITICAL",
      title:       `Storage bucket${scan.publicBuckets!.publicBuckets.length > 1 ? "s" : ""} publicly readable`,
      consequence,
      fix:         "In Supabase Storage, toggle off \"Public bucket\" and add a storage RLS policy scoping access to the owning user.",
    });
  }
  if (scan.rateLimiting?.rateLimited === false && (scan.rateLimiting?.successes ?? 0) >= 8) {
    issues.push({
      severity:    "WARNING",
      title:       "No rate limiting on REST API",
      consequence: "Attackers can enumerate your data at high speed without throttling.",
      fix:         "Add rate limiting via Supabase Edge Functions or a reverse proxy.",
    });
  }
  if (scan.secureAuth?.tested && scan.secureAuth.loginRateLimited === false) {
    issues.push({
      severity:    "WARNING",
      title:       "Login endpoint not rate limited",
      consequence: "Passwords can be brute-forced at high speed.",
      fix:         "Enable auth rate limiting in Supabase Auth settings or add a proxy with rate limiting.",
    });
  }
  if (scan.stackTraceCheck?.exposed) {
    issues.push({
      severity:    "WARNING",
      title:       "Stack traces exposed in error responses",
      consequence: "Internal file paths and line numbers help attackers understand your codebase.",
      fix:         "Return only generic error messages in production; log details server-side only.",
    });
  }
  if (scan.botProtection?.tested && scan.botProtection.rateLimitHeadersPresent === false) {
    issues.push({
      severity:    "WARNING",
      title:       "No rate-limit headers in API responses",
      consequence: "Bots cannot self-throttle and can hammer your API undetected.",
      fix:         "Add X-RateLimit-Limit and X-RateLimit-Remaining headers via Edge Functions or CDN.",
    });
  }

  // A check that did not run is not a pass (1E-5): name them, never hide them.
  const unverified = Object.entries(scan as unknown as Record<string, unknown>)
    .filter(([, check]) => (check as { tested?: unknown } | null)?.tested === false)
    .map(([name]) => name);
  if (unverified.length > 0) {
    issues.push({
      severity:    "INFO",
      title:       `${unverified.length} check${unverified.length === 1 ? "" : "s"} could not be verified`,
      consequence: `These did not run or could not be read, so they are unknown, not safe: ${unverified.join(", ")}.`,
      fix:         "Run the scan again. If a check stays unverified, its target is unreachable or not exposed to the anon key.",
    });
  }

  const summary = issues.length === 0
    ? "All checks passed. No security issues found."
    : `Found ${criticals} critical issue${criticals !== 1 ? "s" : ""} and ${warnings} warning${warnings !== 1 ? "s" : ""}` +
      (unverified.length > 0 ? `, and ${unverified.length} check${unverified.length === 1 ? "" : "s"} could not be verified` : "") +
      ". AI analysis was unavailable, so results are based on raw check data.";

  return { issues, summary };
}

// ── Runtime schema validation ─────────────────────────────────────────────────

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (typeof value !== "object" || value === null) return false;

  const v = value as Record<string, unknown>;

  if (typeof v.summary !== "string" || v.summary.trim() === "") return false;
  if (!Array.isArray(v.issues)) return false;

  return v.issues.every((item) => {
    if (typeof item !== "object" || item === null) return false;
    const i = item as Record<string, unknown>;
    if (
      !VALID_SEVERITIES.has(i.severity as string) ||
      typeof i.title !== "string" ||
      typeof i.consequence !== "string" ||
      typeof i.fix !== "string"
    ) return false;
    if (i.codefix !== undefined) {
      if (typeof i.codefix !== "object" || i.codefix === null) return false;
      const cf = i.codefix as Record<string, unknown>;
      if (typeof cf.file !== "string" || typeof cf.description !== "string" || typeof cf.prompt !== "string") return false;
    }
    return true;
  });
}

// ── Model routing ─────────────────────────────────────────────────────────────

function estimateCriticalCount(scan: ScanResult): number {
  let count = 0;
  if (scan.tables.some(t => !t.rlsEnabled)) count++;
  if (scan.keyAnalysis?.isServiceRole) count++;
  if (scan.unauthAccess?.results?.some(r => r.accessible)) count++;
  if (scan.slopSquatting?.suspiciousPackages?.some(p => p.reason === "NOT_FOUND")) count++;
  if (scan.massAssignment?.results?.some(r => r.vulnerable)) count++;
  if (scan.authSecurity?.adminEndpointBlocked === false) count++;
  if (scan.idor?.results?.some(r => r.rowsAccessible)) count++;
  if ((scan.secretsExposure?.exposedFiles?.length ?? 0) > 0) count++;
  if (scan.httpsCheck?.enforced === false) count++;
  // NOTE: CORS wildcard and detailed PostgREST errors are Supabase PLATFORM
  // DEFAULTS (bearer-token auth makes CORS * a non-CSRF, and detailed errors
  // are standard PostgREST) — they are INFO platform-notes, not criticals, and
  // deliberately do NOT inflate severity. See the analyzer prompt CHECK 13/14.
  if ((scan.publicBuckets?.publicBuckets?.length ?? 0) > 0) count++;
  return count;
}

function selectModel(scan: ScanResult): string {
  const criticalCount = estimateCriticalCount(scan);
  const hasMassAssignment = scan.massAssignment?.results?.some(r => r.vulnerable) ?? false;
  return (criticalCount >= 2 || hasMassAssignment) ? "claude-sonnet-4-6" : "claude-haiku-4-5-20251001";
}

// ── Analyser ──────────────────────────────────────────────────────────────────

export async function analyzeResult(scan: ScanResult): Promise<AnalysisResult> {
  // ShipLock-funded and unbounded per scan: off unless explicitly enabled
  // (3G-2). The deterministic report is the same one used on any model failure.
  if (!shiplockFundedCallAllowed("scan-report")) return buildFallback(scan);
  // ScanResult never contains the anon key — serialising it is safe by design.
  const userMessage = JSON.stringify(scan, null, 2);

  const client = new Anthropic();
  const model  = selectModel(scan);

  let response: Anthropic.Message;
  try {
    response = await client.messages.create(
      {
        model,
        max_tokens: 2500,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: userMessage }],
      },
      {
        timeout: TIMEOUT_MS,
        maxRetries: 0, // prevent retries from silently exceeding the 30s budget
      }
    );
    console.log(`[analyzer] model=${model} input_tokens=${response.usage.input_tokens} output_tokens=${response.usage.output_tokens}`);
  } catch (err) {
    if (err instanceof Anthropic.APIConnectionTimeoutError) {
      console.error("[analyzer] Claude API timed out after 30 s — using fallback analysis");
    } else if (err instanceof Anthropic.AuthenticationError) {
      console.error("[analyzer] Invalid ANTHROPIC_API_KEY — using fallback analysis");
    } else if (err instanceof Anthropic.RateLimitError) {
      console.error("[analyzer] Anthropic API rate limit exceeded — using fallback analysis");
    } else if (err instanceof Anthropic.InternalServerError) {
      console.error("[analyzer] Anthropic internal server error — using fallback analysis");
    } else if (err instanceof Anthropic.APIError) {
      console.error(`[analyzer] Anthropic API error HTTP ${err.status}: ${err.message} — using fallback analysis`);
    } else {
      console.error("[analyzer] Unexpected error during analysis — using fallback analysis");
    }
    return buildFallback(scan);
  }

  // Extract the text block from the response
  const textBlock = response.content.find((b) => b.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    console.error("[analyzer] Claude response contained no text block — using fallback analysis");
    return buildFallback(scan);
  }

  // Strip accidental markdown fences before parsing
  const raw = textBlock.text
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.error("[analyzer] Claude response was not valid JSON — using fallback analysis");
    return buildFallback(scan);
  }

  if (!isAnalysisResult(parsed)) {
    console.error("[analyzer] Claude response failed schema validation — using fallback analysis");
    return buildFallback(scan);
  }

  return parsed;
}

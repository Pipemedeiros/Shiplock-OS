import Anthropic from "@anthropic-ai/sdk";
import type { ScanResult } from "./scanner";

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
  grade: "A" | "B" | "C" | "D" | "F";
  issues: AnalysisIssue[];
  summary: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a Supabase security auditor writing for non-technical startup founders.

You will receive a JSON scan result covering 15 security checks. Analyse every
check and return a single grade plus specific, actionable issues.

═══════════════════════════════════════════════════════════
CHECK 1 — RLS STATUS  (tables[].rlsEnabled)
═══════════════════════════════════════════════════════════
Each table has rlsEnabled, policiesRetrieved, and policies fields.

• rlsEnabled: false
  → CRITICAL. The table is fully exposed — anyone with the anon key can read all rows.
  → Any exposed table drives the grade to D or F.

• rlsEnabled: true + policiesRetrieved: true + policies.length > 0
  → GOOD. RLS is on and policies are confirmed. No issue needed.

• rlsEnabled: true + policiesRetrieved: true + policies.length === 0
  → WARNING. RLS is on (data not exposed) but no policies found. The app itself
    may be locked out. Suggest adding service-role and user-scoped policies.

• rlsEnabled: true + policiesRetrieved: false
  → GOOD (treat as correctly secured). pg_policies was unreadable — empty
    policies array does NOT mean no policies exist. Data is not publicly
    accessible. Grade A or B. Do NOT penalise this.

═══════════════════════════════════════════════════════════
CHECK 2 — KEY TYPE  (keyAnalysis)
═══════════════════════════════════════════════════════════
keyAnalysis fields: role, isServiceRole, jwtValid, projectRef

• isServiceRole: true
  → CRITICAL. The user submitted their master service_role key to a public
    scanner. This key bypasses ALL RLS, can read/write everything, and must
    never leave the server.
  → Fix: rotate the service_role key immediately in the Supabase dashboard,
    and use only the anon key for client-side operations.

• isServiceRole: false, role: "anon"
  → GOOD. Correct key type for scanning.

• jwtValid: false
  → WARNING. The provided key could not be parsed as a JWT. Verify the anon
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

• All results accessible: false OR tested: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 5 — SLOP SQUATTING  (slopSquatting)
═══════════════════════════════════════════════════════════
slopSquatting fields: tested, packageJsonAccessible, suspiciousPackages[]
Each package has: name, reason ("NOT_FOUND"|"VERY_NEW"), createdAt?

• packageJsonAccessible: false OR tested: false → No finding needed.

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

• Any result with vulnerable: true
  → CRITICAL. The API accepted a PATCH containing privileged fields
    (is_paid, is_admin, role). An attacker could escalate their own privileges.
    Fix: use column-level security in RLS policies, or add a trigger that
    strips privileged fields from client updates.

• All vulnerable: false OR tested: false → GOOD.

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

• All rowsAccessible: false OR tested: false → GOOD.

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

• loginRateLimited: true → GOOD.

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

• rateLimitHeadersPresent: true OR tested: false → No issue needed.

═══════════════════════════════════════════════════════════
CHECK 13 — INPUT VALIDATION  (inputValidation)
═══════════════════════════════════════════════════════════
inputValidation fields: tested, sqlErrorExposed

• sqlErrorExposed: true
  → CRITICAL. A crafted query parameter caused the API to return a raw
    PostgreSQL error message. Exposing database internals helps attackers
    map your schema and craft targeted exploits.
    Fix: ensure PostgREST is configured to return generic error messages and
    review any custom SQL functions for injection vulnerabilities.

• sqlErrorExposed: false OR tested: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 14 — CORS CONFIGURATION  (corsConfig)
═══════════════════════════════════════════════════════════
corsConfig fields: tested, wildcardOrigin, allowOriginValue

• wildcardOrigin: true  (allowOriginValue === "*")
  → CRITICAL. The API returns Access-Control-Allow-Origin: * which allows
    any website on the internet to make cross-origin requests to your API.
    A malicious website could trick a logged-in user's browser into sending
    authenticated requests to your database.
    Fix: configure CORS to only allow your specific app domain (e.g.
    https://your-app.com) instead of the wildcard.

• wildcardOrigin: false OR tested: false → GOOD.

═══════════════════════════════════════════════════════════
CHECK 15 — STACK TRACE EXPOSURE  (stackTraceCheck)
═══════════════════════════════════════════════════════════
stackTraceCheck fields: tested, exposed

• exposed: true
  → WARNING. A malformed request returned an error containing internal stack
    trace information (file paths, line numbers, or "Error:" strings).
    Fix: configure your error handler to return only generic error messages
    in production, and log detailed errors server-side only.

• exposed: false OR tested: false → GOOD.

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
GRADE SCALE
═══════════════════════════════════════════════════════════
F  — service_role key submitted, OR 3+ CRITICAL issues
D  — at least one exposed table (rlsEnabled: false), mass assignment, IDOR, or secrets exposed
C  — no exposed tables but multiple WARNINGs
B  — no exposed tables, one minor WARNING
A  — all critical checks passed, no exposed tables, correct key type

═══════════════════════════════════════════════════════════
OUTPUT RULES
═══════════════════════════════════════════════════════════
• Plain English — no jargon, no CVE numbers
• One sentence title; real-world consequence; exact SQL or config fix
• Do not raise issues for checks that passed
• Return ONLY valid JSON:
{
  "grade": "A"|"B"|"C"|"D"|"F",
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

const VALID_GRADES = new Set(["A", "B", "C", "D", "F"]);
const VALID_SEVERITIES = new Set(["CRITICAL", "WARNING", "INFO"]);
const TIMEOUT_MS = 30_000;

// ── Fallback grade from raw check results (used when Claude API is unavailable) ─

function countWarnings(scan: ScanResult): number {
  let count = 0;
  if (scan.rateLimiting?.rateLimited === false && (scan.rateLimiting?.successes ?? 0) >= 8) count++;
  if (scan.botProtection?.rateLimitHeadersPresent === false) count++;
  if (scan.stackTraceCheck?.exposed) count++;
  if (scan.secureAuth?.loginRateLimited === false) count++;
  if (scan.slopSquatting?.suspiciousPackages?.some(p => (p as { reason?: string }).reason === "VERY_NEW")) count++;
  return count;
}

function fallbackGrade(scan: ScanResult): "A" | "B" | "C" | "D" | "F" {
  const criticals = estimateCriticalCount(scan);
  if (criticals >= 3) return "F";
  if (criticals === 2) return "D";
  if (criticals === 1) return "C";
  if (countWarnings(scan) >= 2) return "B";
  return "A";
}

function buildFallback(scan: ScanResult): AnalysisResult {
  const grade = fallbackGrade(scan);
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
      severity:    "CRITICAL",
      title:       "Raw SQL errors exposed to clients",
      consequence: "Error messages reveal your database schema and help attackers craft targeted exploits.",
      fix:         "Configure PostgREST to return generic error messages and review custom SQL functions.",
    });
  }
  if (scan.corsConfig?.wildcardOrigin) {
    issues.push({
      severity:    "CRITICAL",
      title:       "CORS allows any origin (wildcard *)",
      consequence: "Any website can make cross-origin requests to your API on behalf of a logged-in user.",
      fix:         "Set Access-Control-Allow-Origin to your specific app domain instead of *.",
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
  if (scan.secureAuth?.loginRateLimited === false) {
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
  if (scan.botProtection?.rateLimitHeadersPresent === false) {
    issues.push({
      severity:    "WARNING",
      title:       "No rate-limit headers in API responses",
      consequence: "Bots cannot self-throttle and can hammer your API undetected.",
      fix:         "Add X-RateLimit-Limit and X-RateLimit-Remaining headers via Edge Functions or CDN.",
    });
  }

  const gradeLabel: Record<string, string> = { A: "clean", B: "minor warnings", C: "one critical issue", D: "multiple critical issues", F: "critical risk" };
  const summary = issues.length === 0
    ? "All checks passed. No security issues found."
    : `Found ${criticals} critical issue${criticals !== 1 ? "s" : ""} and ${warnings} warning${warnings !== 1 ? "s" : ""}. Grade: ${grade} (${gradeLabel[grade]}). AI analysis was unavailable — results are based on raw check data.`;

  return { grade, issues, summary };
}

// ── Runtime schema validation ─────────────────────────────────────────────────

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (typeof value !== "object" || value === null) return false;

  const v = value as Record<string, unknown>;

  if (!VALID_GRADES.has(v.grade as string)) return false;
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
  if (scan.inputValidation?.sqlErrorExposed) count++;
  if (scan.corsConfig?.wildcardOrigin) count++;
  return count;
}

function selectModel(scan: ScanResult): string {
  const criticalCount = estimateCriticalCount(scan);
  const hasMassAssignment = scan.massAssignment?.results?.some(r => r.vulnerable) ?? false;
  return (criticalCount >= 2 || hasMassAssignment) ? "claude-sonnet-4-6" : "claude-haiku-4-5-20251001";
}

// ── Analyser ──────────────────────────────────────────────────────────────────

export async function analyzeResult(scan: ScanResult): Promise<AnalysisResult> {
  // ScanResult never contains the anon key — serialising it is safe by design.
  const userMessage = JSON.stringify(scan, null, 2);

  const client = new Anthropic();
  const model  = selectModel(scan);

  let response: Anthropic.Message;
  try {
    response = await client.messages.create(
      {
        model,
        max_tokens: 1000,
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
      console.error("[analyzer] Claude API timed out after 30 s — using fallback grade");
    } else if (err instanceof Anthropic.AuthenticationError) {
      console.error("[analyzer] Invalid ANTHROPIC_API_KEY — using fallback grade");
    } else if (err instanceof Anthropic.RateLimitError) {
      console.error("[analyzer] Anthropic API rate limit exceeded — using fallback grade");
    } else if (err instanceof Anthropic.InternalServerError) {
      console.error("[analyzer] Anthropic internal server error — using fallback grade");
    } else if (err instanceof Anthropic.APIError) {
      console.error(`[analyzer] Anthropic API error HTTP ${err.status}: ${err.message} — using fallback grade`);
    } else {
      console.error("[analyzer] Unexpected error during analysis — using fallback grade");
    }
    return buildFallback(scan);
  }

  // Extract the text block from the response
  const textBlock = response.content.find((b) => b.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    console.error("[analyzer] Claude response contained no text block — using fallback grade");
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
    console.error("[analyzer] Claude response was not valid JSON — using fallback grade");
    return buildFallback(scan);
  }

  if (!isAnalysisResult(parsed)) {
    console.error("[analyzer] Claude response failed schema validation — using fallback grade");
    return buildFallback(scan);
  }

  return parsed;
}

import type { ScanResult } from "./scanner";

// The scan report, built from the raw check results alone. ShipLock makes no
// model call (Felipe, 2026-10-01), so there is no model-written variant.

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

// ── Issues from raw check results ─────────────────────────────────────────────

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
  // deliberately do NOT inflate severity.
  if ((scan.publicBuckets?.publicBuckets?.length ?? 0) > 0) count++;
  return count;
}

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
      consequence: "Your Supabase API returns detailed Postgres error messages by default, which reveal column names to anyone who already has your public key. This is standard for this stack and low risk, not SQL injection. Optional hardening, not a hole.",
      fix:         "Optional: reduce PostgREST error verbosity in your Supabase project settings. Not required: RLS, not error opacity, is your real boundary.",
    });
  }
  if (scan.corsConfig?.wildcardOrigin) {
    issues.push({
      severity:    "INFO",
      title:       "Supabase API allows any origin (platform default)",
      consequence: "Supabase's API gateway returns Access-Control-Allow-Origin: * for every project. Because Supabase authenticates by a bearer token in the header (not a cookie) a wildcard origin is not the cross-site (CSRF) risk it would be for a cookie-based app. No action needed.",
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

  // A check that did not run is not a pass: name them, never hide them.
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

// ── Report ────────────────────────────────────────────────────────────────────

export async function analyzeResult(scan: ScanResult): Promise<AnalysisResult> {
  return buildFallback(scan);
}

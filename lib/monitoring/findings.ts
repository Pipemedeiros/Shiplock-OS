import type { ScanResult } from "@/lib/scanner";
import type { Severity } from "@/lib/types";

// Deterministic finding extraction for monitoring — does NOT call Claude.
// Monitoring runs on a schedule (hourly/48h/per-deploy) across every
// monitored user; routing each tick through the paid-user AI analyzer
// (lib/analyzer.ts) would be slow and put real cost behind something meant
// to be a background poll. This mirrors analyzer.ts's buildFallback()
// check-to-issue mapping, but with a stable `id` per finding so the diff
// engine can tell "same issue, still present" from "new issue" — the
// human-facing paid /api/scan response is unaffected and still goes
// through the real (Claude or fallback) analyzer unchanged.
export interface Finding {
  id: string; // stable across scans of the same check/table — the diff key
  severity: Severity;
  title: string;
  consequence: string;
}

export function extractFindings(scan: ScanResult): Finding[] {
  const findings: Finding[] = [];

  if (scan.keyAnalysis?.isServiceRole) {
    findings.push({
      id: "service_role_key",
      severity: "CRITICAL",
      title: "Service role key submitted to a public scanner",
      consequence:
        "Your master key bypasses all RLS and can read or modify every table. Rotate it immediately.",
    });
  }

  for (const t of scan.tables) {
    if (!t.rlsEnabled) {
      findings.push({
        id: `rls:${t.name}`,
        severity: "CRITICAL",
        title: `Row Level Security disabled on "${t.name}"`,
        consequence: `Any user with the anon key can read all rows from ${t.name}.`,
      });
    }
  }

  for (const r of scan.unauthAccess?.results ?? []) {
    if (r.accessible) {
      findings.push({
        id: `unauth_access:${r.tableName}`,
        severity: "CRITICAL",
        title: `"${r.tableName}" readable without any authentication`,
        consequence: "Unauthenticated requests (no API key at all) can read this table's data.",
      });
    }
  }

  for (const r of scan.massAssignment?.results ?? []) {
    if (r.vulnerable) {
      findings.push({
        id: `mass_assignment:${r.tableName}`,
        severity: "CRITICAL",
        title: `Mass assignment allows privilege escalation on "${r.tableName}"`,
        consequence: "An attacker can set privileged fields (e.g. is_paid, is_admin) on their own row.",
      });
    }
  }

  if (scan.authSecurity?.adminEndpointBlocked === false) {
    findings.push({
      id: "auth_admin_endpoint",
      severity: "CRITICAL",
      title: "Auth admin endpoint accessible with anon key",
      consequence: "/auth/v1/admin/users is reachable without the service_role key, exposing the full user list.",
    });
  }

  for (const r of scan.idor?.results ?? []) {
    if (r.rowsAccessible) {
      findings.push({
        id: `idor:${r.tableName}`,
        severity: "CRITICAL",
        title: `User data readable without authentication on "${r.tableName}" (IDOR)`,
        consequence: "Sensitive rows can be read with only the anon key and no user session.",
      });
    }
  }

  if ((scan.secretsExposure?.exposedFiles?.length ?? 0) > 0) {
    findings.push({
      id: "secrets_exposure",
      severity: "CRITICAL",
      title: "Environment file publicly accessible",
      consequence: `Secret files are reachable at the project URL: ${scan.secretsExposure!.exposedFiles.join(", ")}`,
    });
  }

  if (scan.httpsCheck?.enforced === false) {
    findings.push({
      id: "https_not_enforced",
      severity: "CRITICAL",
      title: "HTTPS not enforced",
      consequence: "Traffic including API keys and user data is transmitted in plaintext.",
    });
  }

  if (scan.inputValidation?.sqlErrorExposed) {
    findings.push({
      id: "sql_error_exposed",
      severity: "CRITICAL",
      title: "Raw SQL errors exposed to clients",
      consequence: "Error messages reveal database schema details, helping attackers craft targeted exploits.",
    });
  }

  if (scan.corsConfig?.wildcardOrigin) {
    findings.push({
      id: "cors_wildcard",
      severity: "CRITICAL",
      title: "CORS allows any origin (wildcard *)",
      consequence: "Any website can make cross-origin requests to the API on behalf of a logged-in user.",
    });
  }

  if (scan.rateLimiting?.rateLimited === false && (scan.rateLimiting?.successes ?? 0) >= 8) {
    findings.push({
      id: "no_rate_limiting",
      severity: "WARNING",
      title: "No rate limiting on REST API",
      consequence: "Attackers can enumerate data at high speed without throttling.",
    });
  }

  if (scan.secureAuth?.loginRateLimited === false) {
    findings.push({
      id: "login_not_rate_limited",
      severity: "WARNING",
      title: "Login endpoint not rate limited",
      consequence: "Passwords can be brute-forced at high speed.",
    });
  }

  if (scan.stackTraceCheck?.exposed) {
    findings.push({
      id: "stack_trace_exposed",
      severity: "WARNING",
      title: "Stack traces exposed in error responses",
      consequence: "Internal file paths and line numbers help attackers understand the codebase.",
    });
  }

  if (scan.botProtection?.rateLimitHeadersPresent === false) {
    findings.push({
      id: "no_rate_limit_headers",
      severity: "WARNING",
      title: "No rate-limit headers in API responses",
      consequence: "Bots cannot self-throttle and can hammer the API undetected.",
    });
  }

  return findings;
}

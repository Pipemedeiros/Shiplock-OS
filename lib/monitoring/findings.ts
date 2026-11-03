import type { ScanResult, FastScanResult, PublicBucketCheck } from "@/lib/scanner";
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

// Shared by extractFindings() and extractCriticalFindings() — both scan
// types now check public buckets (scanProject() was extended to call
// checkPublicBuckets() too, see lib/scanner.ts check 16), and must produce
// the exact same id/title/consequence shape for a given bucket name so the
// diff engine treats them as the same finding regardless of which pass
// found it.
function buildPublicBucketFindings(check: PublicBucketCheck | undefined): Finding[] {
  const suspiciousByBucket = new Map<string, string[]>();
  for (const s of check?.suspiciousFiles ?? []) {
    const list = suspiciousByBucket.get(s.bucket) ?? [];
    list.push(s.file);
    suspiciousByBucket.set(s.bucket, list);
  }
  return (check?.publicBuckets ?? []).map((bucketName) => {
    const suspicious = suspiciousByBucket.get(bucketName) ?? [];
    return {
      id: `public_bucket:${bucketName}`,
      severity: "CRITICAL" as const,
      title: `Storage bucket "${bucketName}" is publicly readable`,
      consequence: suspicious.length > 0
        ? `Secret-looking files found in this public bucket: ${suspicious.join(", ")}. Anyone with the anon key can download them without authentication.`
        : `Anyone with the anon key can list and download files from the "${bucketName}" bucket without authentication.`,
    };
  });
}

/** Findings from a full endpoint scan result. */
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
    if (t.rlsReadable && !t.rlsEnabled) {
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
      severity: "INFO",
      title: "Supabase returns detailed database errors (platform default)",
      consequence: "Standard PostgREST behavior: reveals column names to anyone with your public key. Low risk, not SQL injection. Optional hardening.",
    });
  }

  if (scan.corsConfig?.wildcardOrigin) {
    findings.push({
      id: "cors_wildcard",
      severity: "INFO",
      title: "Supabase API allows any origin (platform default)",
      consequence: "Supabase uses header bearer-token auth, not cookies, so wildcard CORS is not a CSRF risk here. No action needed.",
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

  if (scan.secureAuth?.tested && scan.secureAuth.loginRateLimited === false) {
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

  if (scan.botProtection?.tested && scan.botProtection.rateLimitHeadersPresent === false) {
    findings.push({
      id: "no_rate_limit_headers",
      severity: "WARNING",
      title: "No rate-limit headers in API responses",
      consequence: "Bots cannot self-throttle and can hammer the API undetected.",
    });
  }

  findings.push(...buildPublicBucketFindings(scan.publicBuckets));

  return findings;
}

// Counterpart to extractFindings() for the hourly lightweight pass
// (lib/scanner.ts scanCriticalChecks / FastScanResult) — same Finding
// shape, so the diff engine doesn't need to know which scan produced a
// given finding. Deliberately reuses the SAME id strings as extractFindings
// for every check both passes cover (service_role_key, rls:<table>,
// secrets_exposure, and now public_bucket:<name> too, via the shared
// buildPublicBucketFindings() helper above) — this is required for correct
// cross-trigger diffing: runMonitoringPass() diffs against whichever
// snapshot is most recent regardless of trigger source, so an hourly pass
// and a 48h pass must agree on a finding's id or the diff engine would see
// every trigger alternation as a "new" finding and spam alerts.
// Whether a finding id could have been produced by the critical/hourly
// pass (extractCriticalFindings) — used by run.ts to merge snapshots
// correctly across passes of different scope. See run.ts for why this
// matters: without it, a narrower pass would make out-of-scope findings
// look "resolved" (they were just not re-checked), which then makes them
// look "new" again on the next wider pass — a spurious duplicate alert for
// something that was never actually fixed. As of check 16 (public
// buckets), both scanProject() and scanCriticalChecks() cover the full set
// of ids this function recognizes — there is no longer any id that's
// hourly-scope-only vs full-scope-only; this now exists purely so run.ts
// can distinguish "produced by this trigger's own scan" for merge purposes.
export function isCriticalScopeFindingId(id: string): boolean {
  return (
    id === "service_role_key" ||
    id.startsWith("rls:") ||
    id === "secrets_exposure" ||
    id.startsWith("public_bucket:")
  );
}

/** Critical findings from a fast endpoint scan result. */
export function extractCriticalFindings(scan: FastScanResult): Finding[] {
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
    if (t.rlsReadable && !t.rlsEnabled) {
      findings.push({
        id: `rls:${t.name}`,
        severity: "CRITICAL",
        title: `Row Level Security disabled on "${t.name}"`,
        consequence: `Any user with the anon key can read all rows from ${t.name}.`,
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

  findings.push(...buildPublicBucketFindings(scan.publicBuckets));

  return findings;
}

import { getSupabaseAdmin } from "@/lib/supabase";
import { getScanTimeline } from "@/lib/scanHistory";
import { getWatchStatus } from "@/lib/monitoring/watchLog";
import { getProtectionStatus } from "@/lib/traffic/trafficLog";
import { auditJwtSigning } from "@/lib/security/sessionAudit";

// "ShipLock Verified" — a shareable, honestly-scoped security-posture
// attestation a customer can hand to their own investors / enterprise buyers.
//
// HARD RULES (why this file is deliberately narrow):
//  - It attests PROCESS + CURRENT POSTURE, never a guarantee. No "certified
//    secure" / "unhackable" language anywhere.
//  - It is a public projection reachable by an unguessable token with NO
//    session, so it must be attacker-safe: posture + scope + cadence only —
//    NEVER the specific findings/titles/fixes, the project URL, or any key.
//  - It degrades honestly: a lapsed subscriber's report drops to `inactive`
//    (no forged/stale green badge).
// buildVerifiedReport is pure so all of this is unit-testable.

const RECENT_SCAN_WINDOW_MS = 72 * 60 * 60 * 1000; // "recently verified" = within 72h
const TOTAL_CHECKS = 16; // lib/scanner.ts always runs the same 16 checks

// Honest, non-technical scope statements. Covered = what our automated surface
// actually tests; NotCovered mirrors CLAUDE.md / the /owasp "what we
// can't scan" section so the attestation reads as credible to a real reviewer.
export const SCOPE_COVERED: string[] = [
  "Row-level access control on the database (RLS presence + policy logic)",
  "Publicly exposed data, tables, and storage buckets",
  "Exposed secrets and committed credentials",
  "Known-vulnerable dependencies (CVEs)",
  "Security misconfiguration and session-token signing",
  "Continuous monitoring for new issues on every pull request",
];
export const SCOPE_NOT_COVERED: string[] = [
  "Deep business-logic flaws unique to the application",
  "Runtime-only vulnerabilities that need a live exploit to confirm",
  "Manual penetration testing depth",
];

export type VerifiedStatus = "verified" | "inactive";
export type SessionSigning = "asymmetric" | "legacy" | "unknown" | null;

// Raw inputs assembled by getVerifiedReport, kept separate from the DB so the
// projection logic is pure/testable.
export interface VerifiedReportData {
  isPaid: boolean;
  enabled: boolean; // verified_report_enabled
  monitoringEnabled: boolean;
  lastScanAt: string | null;
  projectHashSuffix: string | null; // last 6 of project_url_hash — an anonymous identifier, never the URL
  openCriticalCount: number;
  openIssueCount: number; // total open scan issues (drives checksPassing)
  issuesResolved: number; // net issues resolved since monitoring began (>= 0)
  trafficInstalled: boolean;
  sessionSigning: SessionSigning;
  nowMs: number;
}

export interface VerifiedReport {
  status: VerifiedStatus;
  monitored: boolean;
  clean: boolean; // no open critical issues
  lastVerifiedAt: string | null;
  cadence: string[]; // human-readable monitoring cadence
  checksPassing: number;
  totalChecks: number;
  openCriticalCount: number;
  issuesResolved: number;
  trafficProtection: boolean;
  sessionSigning: SessionSigning;
  projectHashSuffix: string | null;
  scopeCovered: string[];
  scopeNotCovered: string[];
  // The honest boundary line, rendered prominently on the report.
  disclaimer: string;
}

const DISCLAIMER =
  "This attests that the application is under continuous automated security monitoring by ShipLock and its current posture on the checks below. " +
  "It is not a guarantee that the application is free of all vulnerabilities — no automated tool can promise that. See the scope for what is and isn't covered.";

/**
 * Pure projection. Decides verified-vs-inactive and produces only
 * attacker-safe, paywall-safe posture fields.
 */
export function buildVerifiedReport(d: VerifiedReportData): VerifiedReport {
  const recent =
    d.lastScanAt != null &&
    !Number.isNaN(Date.parse(d.lastScanAt)) &&
    d.nowMs - Date.parse(d.lastScanAt) <= RECENT_SCAN_WINDOW_MS;

  // A live "verified" badge requires an active paid subscription, the owner
  // having opted the report public, monitoring on, and a recent scan. Anything
  // else degrades to `inactive` — the report still renders, honestly, without a
  // live badge.
  const status: VerifiedStatus =
    d.isPaid && d.enabled && d.monitoringEnabled && recent ? "verified" : "inactive";

  const checksPassing = Math.max(0, TOTAL_CHECKS - Math.max(0, d.openIssueCount));

  return {
    status,
    monitored: d.monitoringEnabled && d.isPaid,
    clean: d.openCriticalCount === 0,
    lastVerifiedAt: d.lastScanAt,
    cadence: ["On every pull request", "Hourly critical-check pass", "Full deep scan every 48h"],
    checksPassing,
    totalChecks: TOTAL_CHECKS,
    openCriticalCount: Math.max(0, d.openCriticalCount),
    issuesResolved: Math.max(0, d.issuesResolved),
    trafficProtection: d.trafficInstalled,
    sessionSigning: d.sessionSigning,
    projectHashSuffix: d.projectHashSuffix,
    scopeCovered: SCOPE_COVERED,
    scopeNotCovered: SCOPE_NOT_COVERED,
    disclaimer: DISCLAIMER,
  };
}

// Service-role read by token (same auth-by-unguessable-token pattern as
// app/api/monitor/vercel/[token]). Returns null when the token doesn't match a
// row at all — the page renders a generic "no active report" either way, so a
// disabled report is indistinguishable from a nonexistent one (no enumeration).
export async function getVerifiedReport(token: string): Promise<VerifiedReport | null> {
  if (!token) return null;
  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from("user_profiles")
    .select(
      "id, is_paid, verified_report_enabled, monitoring_enabled, last_monitored_at, monitored_project_url"
    )
    .eq("verified_report_token", token)
    .maybeSingle();

  if (!profile) return null;
  const userId = profile.id as string;

  // Latest scan + timeline (counts only — preview-safe), monitoring status,
  // traffic install state. Deep findings' open-critical count. Session signing
  // is best-effort from the stored project URL (used server-side only, never
  // returned).
  const [timeline, watchStatus, protection, deepCritical] = await Promise.all([
    getScanTimeline(userId, 30),
    getWatchStatus(userId),
    getProtectionStatus(userId),
    admin
      .from("deep_findings")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("severity", "CRITICAL")
      .is("archived_at", null),
  ]);

  const latestCount = timeline[0]?.issue_count ?? 0;
  // Net issues resolved since monitoring began: the earliest recorded open
  // count minus the current one, floored at 0. Honest and simple.
  const earliestCount = timeline.length ? timeline[timeline.length - 1].issue_count ?? 0 : 0;
  const issuesResolved = Math.max(0, earliestCount - latestCount);

  let sessionSigning: SessionSigning = null;
  const projectUrl = profile.monitored_project_url as string | null | undefined;
  if (projectUrl) {
    try {
      const posture = await auditJwtSigning(projectUrl);
      sessionSigning = posture.ok ? "asymmetric" : posture.title.includes("determine") ? "unknown" : "legacy";
    } catch {
      sessionSigning = "unknown";
    }
  }

  // Project hash suffix as an anonymous identifier (never the URL). We only
  // have the hash on scan_history, not the profile — fetch just the suffix.
  const { data: lastScan } = await admin
    .from("scan_history")
    .select("project_url_hash")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  const hash = (lastScan?.project_url_hash as string | null) ?? null;

  return buildVerifiedReport({
    isPaid: Boolean(profile.is_paid),
    enabled: Boolean(profile.verified_report_enabled),
    monitoringEnabled: Boolean(profile.monitoring_enabled),
    lastScanAt: (watchStatus.lastDeepScanAt as string | null) ?? timeline[0]?.created_at ?? null,
    projectHashSuffix: hash ? hash.slice(-6) : null,
    openCriticalCount: deepCritical.count ?? 0,
    openIssueCount: latestCount,
    issuesResolved,
    trafficInstalled: protection.installed,
    sessionSigning,
    nowMs: Date.now(),
  });
}

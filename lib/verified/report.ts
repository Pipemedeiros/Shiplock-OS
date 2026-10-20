import { isConfirmed } from "@/lib/agent/confirmed";
import { isLiveSource, liveEvidence } from "@/lib/agent/liveFindings";
import type { Claim, Confidence } from "@/lib/agent/findings";
import type { Severity } from "@/lib/types";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { UnassessedSummary } from "@/lib/agent/unassessed";

// "ShipLock Verified" — a shareable, honestly-scoped statement of what the last
// audit assessed and what it found, addressed by an unguessable token.
//
// REBUILT 2026-09-03 against the audit pipeline. The previous version was built
// on the superseded external scanner and could not be made honest by editing:
// it computed "passing N of 16 checks" as sixteen minus a scan-issue count that
// is zero for an account that never ran that scan, so a project which had never
// been checked rendered sixteen of sixteen; it named an hourly pass nothing
// triggers; and its badge read `is_paid`, false for everyone while billing is
// parked. Every number below comes from `audit_runs` and `deep_findings`.
//
// HARD RULES, and each is asserted in report.test.ts:
//  - THE DISCLOSURE LEADS. The share of the surface we could not judge is in
//    the headline sentence, not below it. A report that says "no critical
//    findings" while silently assessing a fifth of the endpoints is the exact
//    failure "absent is not clean" exists to prevent, and this is the surface
//    where it would cost the most.
//  - An absent measurement is never rendered as a clean one. A run from before
//    the disclosure has `unassessed: null` and says so.
//  - Attacker-safe: counts and boundaries only. Never a finding title, an
//    endpoint path, a table name, or the repository's contents.
//  - No billing state. Whether someone pays has nothing to do with what an
//    audit found.
//
// buildVerifiedReport is pure, so all of this is unit-testable.

/** Older than this and the page says so rather than presenting it as current. */
const STALE_AFTER_DAYS = 30;

export interface VerifiedRunData {
  fullName: string;
  commitSha: string | null;
  finishedAt: string | null;
  trigger: string;
  filesRead: number | null;
  entriesFound: number | null;
  tablesFound: number | null;
  /** Null for a run that predates the disclosure. Never treated as zero. */
  unassessed: UnassessedSummary | null;
}

export interface VerifiedReportData {
  /** The owner published this report. */
  enabled: boolean;
  /** The most recent COMPLETED run, or null when there has never been one. */
  run: VerifiedRunData | null;
  openCritical: number;
  openTotal: number;
  hasDatabase: boolean;
  /** The live site's last read, only when its address is bound to this repository. */
  live?: VerifiedLiveData | null;
  nowMs: number;
}

/** Counts from the outside view; never the address or a path. */
export interface VerifiedLiveData {
  readAt: string | null;
  complete: boolean;
  pages: number;
  scriptsRead: number;
  scriptsSeen: number;
  /** Open findings for a secret key found in the shipped JavaScript. */
  shippedSecrets: number;
}

export type VerifiedStatus = "assessed" | "never_assessed";

/** The assessed/unassessed split, or `{ known: false }` for a run that predates it. */
export type Assessment =
  | { known: false }
  | {
      known: true;
      dataTouching: number;
      assessed: number;
      unassessed: number;
      /** Percentage of data-touching endpoints we could not judge, 0-100. */
      unassessedShare: number;
      reasons: { identity: number; scope: number; signature: number };
      dataUnreadable: number;
    };

export interface VerifiedReport {
  status: VerifiedStatus;
  repository: string | null;
  /** Short commit sha, or null when the run recorded none. */
  commit: string | null;
  assessedAt: string | null;
  ageDays: number | null;
  stale: boolean;
  trigger: string | null;
  read: { files: number; entries: number; tables: number } | null;
  assessment: Assessment | null;
  openCritical: number;
  openTotal: number;
  /** What this assessment did not look at, in the reader's terms. */
  notCovered: string[];
  /** What the live site showed, as sentences with counts only; null when it was not read for this report. */
  live: string[] | null;
  /** The one-sentence result, with the limitation inside it. */
  headline: string;
  disclaimer: string;
}

const DISCLAIMER =
  "This states what ShipLock's last automated review of this repository assessed and what it found. " +
  "It is not a security certification, an audit opinion, a penetration test, or a compliance attestation, " +
  "and no automated review can establish that an application is free of vulnerabilities. " +
  "It is published by the repository's owner for information only.";

function notCoveredFor(hasDatabase: boolean, liveRead: boolean): string[] {
  return [
    ...(hasDatabase
      ? []
      : ["The access rules in the database itself. Row-level policies live there, not in the code, and no database is connected to this report."]),
    ...(liveRead
      ? []
      : ["What the live site ships to visitors. Its address is not linked to this repository, so it was not read for this report."]),
    "Runtime configuration: environment variable values, provider dashboard settings, and anything that is not in the repository.",
    "Business logic specific to this application, where correct behaviour is a matter of intent rather than structure.",
    "Anything that needs the application running. This is a read of source code, not a penetration test, and nothing was attacked.",
  ];
}

const day = (iso: string | null) => iso && !Number.isNaN(Date.parse(iso))
  ? new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }) : "an unrecorded date";

/** The live site in two sentences: how much was read, and what it showed. */
function liveLines(l: VerifiedLiveData): string[] {
  const scripts = l.complete ? `${l.scriptsRead} scripts` : `${l.scriptsRead} of ${l.scriptsSeen} scripts`;
  const read = `${l.complete ? "Read completely" : "Partly read"} on ${day(l.readAt)}: ${l.pages} ${l.pages === 1 ? "page" : "pages"} and ${scripts}, as any visitor gets them.`;
  const found = l.shippedSecrets > 0 ? `${l.shippedSecrets} found` : "none found";
  return [read, `Secret keys in that JavaScript: ${found}${l.complete ? "." : ", and the rest is unknown."}`];
}

/** Pure projection. Everything the public page renders comes from here. */
export function buildVerifiedReport(d: VerifiedReportData): VerifiedReport {
  const notCovered = notCoveredFor(d.hasDatabase, Boolean(d.live));
  const live = d.live ? liveLines(d.live) : null;

  if (!d.run) {
    return {
      status: "never_assessed",
      repository: null,
      commit: null,
      assessedAt: null,
      ageDays: null,
      stale: false,
      trigger: null,
      read: null,
      assessment: null,
      openCritical: 0,
      openTotal: 0,
      notCovered,
      live,
      headline: "No completed assessment. Nothing on this page has been checked.",
      disclaimer: DISCLAIMER,
    };
  }

  const finishedMs = d.run.finishedAt ? Date.parse(d.run.finishedAt) : NaN;
  const ageDays = Number.isNaN(finishedMs) ? null : Math.floor((d.nowMs - finishedMs) / 86_400_000);

  const u = d.run.unassessed;
  const assessment: Assessment = u
    ? {
        known: true,
        dataTouching: u.dataTouching,
        assessed: u.dataTouching - u.unassessed,
        unassessed: u.unassessed,
        unassessedShare: u.dataTouching > 0 ? Math.round((100 * u.unassessed) / u.dataTouching) : 0,
        reasons: u.reasons,
        dataUnreadable: u.dataUnreadable,
      }
    : { known: false };

  // THE HEADLINE CARRIES THE LIMITATION. "No critical findings" on its own is
  // the sentence a reader would quote, and on its own it is not true of the
  // whole surface -- only of the part we could judge. So the denominator is in
  // the same sentence, always, and unresolved criticals lead when there are any.
  const scope = assessment.known
    ? `the ${assessment.assessed} of ${assessment.dataTouching} endpoints that could be assessed`
    : "the endpoints that could be assessed";
  const headline = !assessment.known
    ? d.openCritical > 0
      ? `${d.openCritical} unresolved critical ${d.openCritical === 1 ? "finding" : "findings"}. This assessment predates the record of how much of the surface could be judged.`
      : "No critical findings, but this assessment predates the record of how much of the surface could be judged."
    : d.openCritical > 0
      ? `${d.openCritical} unresolved critical ${d.openCritical === 1 ? "finding" : "findings"} on ${scope}`
      : `No critical findings on ${scope}`;

  return {
    status: "assessed",
    repository: d.run.fullName,
    commit: d.run.commitSha ? d.run.commitSha.slice(0, 7) : null,
    assessedAt: d.run.finishedAt,
    ageDays,
    stale: ageDays !== null && ageDays > STALE_AFTER_DAYS,
    trigger: d.run.trigger,
    read:
      d.run.filesRead !== null && d.run.entriesFound !== null
        ? { files: d.run.filesRead, entries: d.run.entriesFound, tables: d.run.tablesFound ?? 0 }
        : null,
    assessment,
    openCritical: Math.max(0, d.openCritical),
    openTotal: Math.max(0, d.openTotal),
    notCovered,
    live,
    headline,
    disclaimer: DISCLAIMER,
  };
}

/**
 * Service-role read by token, no session — the same unguessable-token model as
 * the deploy webhook. Returns null when the token matches no published report,
 * so a disabled report and a nonexistent one are indistinguishable and the
 * token space cannot be enumerated.
 */
/** Open counts as the dashboard status counts them: confirmed issues only (A1). */
export function confirmedCounts(rows: { severity: unknown; confidence: unknown; attack_class: unknown; claims: unknown; source?: unknown; finding_id?: unknown }[]):
  { openCritical: number; openTotal: number } {
  const confirmed = rows.filter((r) => {
    // W3: a live row's evidence is where it was read, as on the dashboard.
    const live = isLiveSource(String(r.source)) ? liveEvidence({ source: String(r.source), finding_id: String(r.finding_id) }) : null;
    return isConfirmed({ severity: r.severity as Severity, confidence: live?.confidence ?? (r.confidence as Confidence) ?? "inferred",
      attackClass: live?.attackClass ?? String(r.attack_class ?? ""), claims: live?.claims ?? (Array.isArray(r.claims) ? (r.claims as Claim[]) : []) });
  });
  return { openCritical: confirmed.filter((r) => r.severity === "CRITICAL").length, openTotal: confirmed.length };
}

/** The live site's counts for this report, only under a current binding to
 * the report's repository and for a read of that same address (P5 rules). */
export function verifiedLive(input: { url: unknown; boundUrl: unknown; boundRepository: string | null; reportRepository: string | null;
  surface: Record<string, unknown> | null; recordedAt: string | null; openFindingIds: readonly string[] }): VerifiedLiveData | null {
  const { url, surface } = input;
  if (typeof url !== "string" || input.boundUrl !== url || !input.boundRepository || !input.reportRepository
    || input.boundRepository.toLowerCase() !== input.reportRepository.toLowerCase() || !surface || surface.url !== url) return null;
  const count = (v: unknown) => (typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : 0);
  return { readAt: input.recordedAt, complete: surface.complete === true, pages: count(surface.pagesRead),
    scriptsRead: count(surface.scriptsRead), scriptsSeen: count(surface.scriptsSeen),
    shippedSecrets: input.openFindingIds.filter((id) => id.startsWith("bundle:shipped_secret:")).length };
}

export async function getVerifiedReport(token: string): Promise<VerifiedReport | null> {
  if (!token) return null;
  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from("user_profiles")
    .select("id, verified_report_enabled, supabase_project_ref, postgres_display, monitored_app_url, monitored_app_bound_url, monitored_app_repository_id")
    .eq("verified_report_token", token)
    .maybeSingle();

  if (!profile || !profile.verified_report_enabled) return null;
  const userId = profile.id as string;

  const [runRes, openRes, boundRes, factsRes] = await Promise.all([
    admin
      .from("audit_runs")
      .select("full_name, commit_sha, finished_at, trigger, files_read, entries_found, tables_found, unassessed")
      .eq("user_id", userId)
      .eq("status", "complete")
      .order("finished_at", { ascending: false })
      .limit(1)
      .maybeSingle(),
    admin
      .from("deep_findings")
      .select("source, finding_id, severity, confidence, attack_class, claims")
      .eq("user_id", userId)
      .is("archived_at", null)
      .limit(2000),
    profile.monitored_app_repository_id
      ? admin.from("repositories").select("full_name").eq("id", profile.monitored_app_repository_id).eq("user_id", userId).eq("selected", true).maybeSingle()
      : Promise.resolve({ data: null }),
    admin.from("graph_facts").select("facts").eq("user_id", userId).eq("collector", "runtime").maybeSingle(),
  ]);
  const counts = confirmedCounts((openRes.data ?? []) as Parameters<typeof confirmedCounts>[0]);

  const row = runRes.data as Record<string, unknown> | null;
  const facts = (factsRes.data?.facts ?? null) as { appSurface?: Record<string, unknown>; _evidence?: { fields?: { appSurface?: { recordedAt?: unknown } } } } | null;
  const recordedAt = facts?._evidence?.fields?.appSurface?.recordedAt;
  const live = verifiedLive({ url: profile.monitored_app_url, boundUrl: profile.monitored_app_bound_url,
    boundRepository: (boundRes.data as { full_name?: string } | null)?.full_name ?? null, reportRepository: row ? String(row.full_name) : null,
    surface: facts?.appSurface ?? null, recordedAt: typeof recordedAt === "string" ? recordedAt : null,
    openFindingIds: ((openRes.data ?? []) as { finding_id?: unknown }[]).map((r) => String(r.finding_id ?? "")) });

  return buildVerifiedReport({
    enabled: true,
    run: row
      ? {
          fullName: String(row.full_name),
          commitSha: (row.commit_sha as string | null) ?? null,
          finishedAt: (row.finished_at as string | null) ?? null,
          trigger: String(row.trigger ?? "manual"),
          filesRead: (row.files_read as number | null) ?? null,
          entriesFound: (row.entries_found as number | null) ?? null,
          tablesFound: (row.tables_found as number | null) ?? null,
          unassessed: (row.unassessed as UnassessedSummary | null) ?? null,
        }
      : null,
    openCritical: counts.openCritical,
    openTotal: counts.openTotal,
    hasDatabase: Boolean(profile.supabase_project_ref || profile.postgres_display),
    live,
    nowMs: Date.now(),
  });
}

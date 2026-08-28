import { getSupabaseAdmin } from "@/lib/supabase";
import type { Claim, Confidence, FixKind } from "./findings";
import type { CoverageNote, TraceStep } from "./audit";
import type { Severity } from "@/lib/types";

/**
 * Everything the dashboard reads.
 *
 * Loaded through the service-role client, the same way scan history is: these
 * tables describe a customer's private architecture and have no grants for
 * `authenticated`. Nothing here reaches a client component that has not been
 * filtered first.
 */

export interface DashboardFinding {
  rowId: string;
  id: string;
  title: string;
  consequence: string;
  severity: Severity;
  confidence: Confidence;
  attackClass: string;
  entry: string | null;
  file: string | null;
  blastRadius: string | null;
  fixKind: FixKind;
  claims: Claim[];
  repository: string | null;
  detectedAt: string;
  fixPrUrl: string | null;
  fixPrNumber: number | null;
}

export interface DashboardRun {
  id: string;
  fullName: string;
  status: string;
  trigger: string;
  startedAt: string;
  finishedAt: string | null;
  findingsCount: number;
  entriesFound: number | null;
  tablesFound: number | null;
  filesRead: number | null;
  trace: TraceStep[];
  coverage: CoverageNote[];
  error: string | null;
}

export interface DashboardRepo {
  id: string;
  fullName: string;
  lastAuditAt: string | null;
}

function severityRank(severity: Severity): number {
  return severity === "CRITICAL" ? 0 : severity === "WARNING" ? 1 : 2;
}

export async function getOpenFindings(userId: string): Promise<DashboardFinding[]> {
  const admin = getSupabaseAdmin();

  const { data } = await admin
    .from("deep_findings")
    .select(
      "id, finding_id, title, consequence, severity, confidence, attack_class, entry, file, blast_radius, fix_kind, claims, detected_at, fix_pr_url, fix_pr_number, repository_id, repositories(full_name)",
    )
    .eq("user_id", userId)
    .eq("source", "agent")
    .is("archived_at", null)
    .order("detected_at", { ascending: false });

  const rows = (data ?? []) as unknown as Array<Record<string, unknown>>;

  return rows
    .map((row) => {
      const repo = row.repositories as { full_name?: string } | null;
      return {
        rowId: String(row.id),
        id: String(row.finding_id),
        title: String(row.title),
        consequence: String(row.consequence),
        severity: (row.severity as Severity) ?? "WARNING",
        // A missing confidence is `inferred`, never the flattering default. An
        // older row that predates the column has not been proven of anything.
        confidence: (row.confidence as Confidence) ?? "inferred",
        attackClass: String(row.attack_class ?? "unknown"),
        entry: (row.entry as string) ?? null,
        file: (row.file as string) ?? null,
        blastRadius: (row.blast_radius as string) ?? null,
        fixKind: (row.fix_kind as FixKind) ?? "manual",
        claims: Array.isArray(row.claims) ? (row.claims as Claim[]) : [],
        repository: repo?.full_name ?? null,
        detectedAt: String(row.detected_at),
        fixPrUrl: (row.fix_pr_url as string) ?? null,
        fixPrNumber: (row.fix_pr_number as number) ?? null,
      };
    })
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

export async function getRuns(userId: string, limit = 20): Promise<DashboardRun[]> {
  const admin = getSupabaseAdmin();

  const { data } = await admin
    .from("audit_runs")
    .select("*")
    .eq("user_id", userId)
    .order("started_at", { ascending: false })
    .limit(limit);

  return ((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
    id: String(row.id),
    fullName: String(row.full_name),
    status: String(row.status),
    trigger: String(row.trigger),
    startedAt: String(row.started_at),
    finishedAt: (row.finished_at as string) ?? null,
    findingsCount: Number(row.findings_count ?? 0),
    entriesFound: (row.entries_found as number) ?? null,
    tablesFound: (row.tables_found as number) ?? null,
    filesRead: (row.files_read as number) ?? null,
    trace: Array.isArray(row.trace) ? (row.trace as TraceStep[]) : [],
    coverage: Array.isArray(row.coverage) ? (row.coverage as CoverageNote[]) : [],
    error: (row.error as string) ?? null,
  }));
}

export async function getRepositories(userId: string): Promise<DashboardRepo[]> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("repositories")
    .select("id, full_name, last_audit_at")
    .eq("user_id", userId)
    .eq("selected", true)
    .order("full_name");

  return ((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
    id: String(row.id),
    fullName: String(row.full_name),
    lastAuditAt: (row.last_audit_at as string) ?? null,
  }));
}

/** Findings closed since a given point, for the "what changed" panel. */
export async function getRecentlyClosed(userId: string, days = 30): Promise<{ title: string; when: string }[]> {
  const admin = getSupabaseAdmin();
  const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();

  const { data } = await admin
    .from("deep_findings")
    .select("title, archived_at")
    .eq("user_id", userId)
    .eq("source", "agent")
    .not("archived_at", "is", null)
    .gte("archived_at", cutoff)
    .order("archived_at", { ascending: false })
    .limit(10);

  return ((data ?? []) as Array<Record<string, unknown>>).map((row) => ({
    title: String(row.title),
    when: String(row.archived_at),
  }));
}

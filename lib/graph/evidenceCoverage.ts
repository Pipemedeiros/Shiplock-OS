import { getSupabaseAdmin } from "@/lib/supabase";

const LABELS: Record<string, { name: string; fields: Record<string, string> }> = {
  source: { name: "Repository evidence", fields: { routes: "Application routes", dependencies: "Dependencies", liveFiles: "Reachable files", hasEntryPoints: "Application entry points" } },
  db: { name: "Database evidence", fields: { scanTables: "Database tables", policies: "Database access rules", advisors: "Database advisories", authConfig: "Sign-in settings", inventory: "Database structure", authzProvider: "Database access engine" } },
  runtime: { name: "Deployment evidence", fields: { providersRead: "Deployment providers", envVars: "Environment configuration" } },
  traffic: { name: "Traffic evidence", fields: { hotPaths: "Observed route activity" } },
};

export interface EvidenceCoverageItem {
  label: string;
  recordedAt: string | null;
  completeness: "complete" | "partial" | "unknown";
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

/** Display only known metadata fields. Never expose provider facts or reasons. */
export function summarizeEvidence(rows: unknown[], now = Date.now()): EvidenceCoverageItem[] {
  const items: EvidenceCoverageItem[] = [];
  for (const value of rows) {
    const row = object(value);
    const label = typeof row.collector === "string" && Object.hasOwn(LABELS, row.collector)
      ? LABELS[row.collector] : undefined;
    if (!label) continue;
    const metadata = object(row.evidence);
    const fields = metadata.version === 1 ? object(metadata.fields) : {};
    let found = false;
    for (const [key, name] of Object.entries(label.fields)) {
      if (!Object.hasOwn(fields, key)) continue;
      found = true;
      const observation = object(fields[key]);
      const date = typeof observation.recordedAt === "string" ? Date.parse(observation.recordedAt) : NaN;
      const recordedAt = Number.isFinite(date) && date <= now ? new Date(date).toISOString() : null;
      items.push({
        label: name, recordedAt,
        completeness: recordedAt && (observation.completeness === "complete" || observation.completeness === "partial")
          ? observation.completeness : "unknown",
      });
    }
    if (!found) items.push({ label: label.name, recordedAt: null, completeness: "unknown" });
  }
  return items;
}

/** Caller supplies the authenticated dashboard user, never a query parameter. */
export async function getEvidenceCoverage(userId: string): Promise<{ available: boolean; items: EvidenceCoverageItem[] }> {
  try {
    const { data, error } = await getSupabaseAdmin()
      .from("graph_facts")
      .select("collector, evidence:facts->_evidence")
      .eq("user_id", userId);
    if (error) return { available: false, items: [] };
    return { available: true, items: summarizeEvidence(data ?? []) };
  } catch {
    return { available: false, items: [] };
  }
}

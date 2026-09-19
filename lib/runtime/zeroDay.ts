import { getSupabaseAdmin } from "@/lib/supabase";
import { queryOsv } from "@/lib/deep/github";
import { depFindings } from "@/lib/deep/githubScan";
import { loadRepositoryDependencies } from "@/lib/graph/repositorySource";

/** Historical helper. Deduplication must also compare repository identity. */
export function stripRepoPrefix(id: string): string {
  const at = id.indexOf("::");
  return at === -1 ? id : id.slice(at + 2);
}

/** Partial inventories can add findings but never resolve absent advisories. */
export async function runZeroDayCheck(userId: string): Promise<{ total: number; newCount: number; resolvedCount: number }> {
  const admin = getSupabaseAdmin();
  let total = 0, newCount = 0;
  for (const inventory of await loadRepositoryDependencies(userId)) {
    if (!inventory.dependencies.length) continue;
    let findings;
    try { findings = depFindings(await queryOsv(inventory.dependencies)); }
    catch { continue; }
    const [existing, source] = await Promise.all([
      admin.from("deep_findings").select("finding_id").eq("user_id", userId).eq("source", "zero-day").is("archived_at", null),
      admin.from("deep_findings").select("finding_id").eq("user_id", userId).eq("source", "github").is("archived_at", null),
    ]);
    if (existing.error || source.error) throw new Error("Dependency findings unavailable");
    const active = new Set([...(existing.data ?? []), ...(source.data ?? [])].map((row) => String(row.finding_id).toLowerCase()));
    const prefix = inventory.repositoryFullName + "::";
    const fresh = findings.filter((finding) => !active.has((prefix + finding.id).toLowerCase()));
    if (fresh.length) {
      const { error } = await admin.from("deep_findings").insert(fresh.map((finding) => ({
        user_id: userId, repository_id: inventory.repositoryId, source: "zero-day", finding_id: prefix + finding.id,
        severity: finding.severity, title: finding.title,
        consequence: finding.consequence + "\n\nFound by re-checking recorded dependencies for " + inventory.repositoryFullName +
          ". Source coverage is partial; absent advisories do not resolve earlier findings.",
        package_name: finding.packageName, version: finding.version, vuln_id: finding.vulnId, cve_id: finding.cveId,
      })));
      if (error) throw new Error("Dependency findings could not be saved");
    }
    total += findings.length; newCount += fresh.length;
  }
  return { total, newCount, resolvedCount: 0 };
}

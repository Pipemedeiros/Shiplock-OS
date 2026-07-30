import { getSupabaseAdmin } from "@/lib/supabase";
import { queryOsv } from "@/lib/deep/github";
import { depFindings } from "@/lib/deep/githubScan";
import type { SourceFacts } from "@/lib/graph/graphRun";

// F1 — zero-day response.
//
// The gap this closes is easy to miss and completely real: dependency CVEs are
// only checked when a pull request fires the source scan. A customer who ships
// nothing for a month therefore gets NO new-CVE detection for a month — and the
// dangerous case is precisely that one, because the vulnerability arrives from
// the outside world rather than from their own code. Their app did not change;
// the world's knowledge about it did.
//
// So: keep the dependency inventory from the last source scan, and re-query OSV
// on the scheduled pass. Nothing needs to be pushed for a newly-published CVE in
// a package they already depend on to reach them.

export async function runZeroDayCheck(
  userId: string
): Promise<{ total: number; newCount: number; resolvedCount: number }> {
  const admin = getSupabaseAdmin();

  const { data } = await admin
    .from("graph_facts")
    .select("facts")
    .eq("user_id", userId)
    .eq("collector", "source")
    .maybeSingle();

  const deps = ((data?.facts ?? {}) as SourceFacts).dependencies ?? [];
  // No inventory means the source scan has never run. That is "we don't know",
  // and must not archive existing dependency findings.
  if (deps.length === 0) return { total: 0, newCount: 0, resolvedCount: 0 };

  let findings;
  try {
    findings = depFindings(await queryOsv(deps));
  } catch {
    // OSV unreachable. Silence, not a clean bill of health — and critically, no
    // archiving, or an outage at OSV would mark every real CVE as resolved.
    return { total: 0, newCount: 0, resolvedCount: 0 };
  }

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "zero-day")
    .is("archived_at", null);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  // A CVE that no longer applies means they upgraded. Worth closing promptly:
  // the customer did the work and should see it land.
  const resolved = [...active].filter((id) => !current.has(id));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("source", "zero-day")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "zero-day",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence:
          `${f.consequence}\n\n` +
          `This was found by re-checking the dependencies from your last source scan against newly-published advisories. ` +
          `Your code did not change — what changed is that this vulnerability is now public, which also means it is now being looked for.`,
        package_name: f.packageName,
        version: f.version,
        vuln_id: f.vulnId,
        cve_id: f.cveId,
      }))
    );
  }

  return { total: findings.length, newCount: fresh.length, resolvedCount: resolved.length };
}

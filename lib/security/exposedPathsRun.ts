import { getSupabaseAdmin } from "@/lib/supabase";
import { probeExposedPaths, type ExposedFinding } from "./exposedPaths";
import { auditShippedBundle } from "./bundleAudit";

// Everything we can learn from the customer's app URL alone, in one pass:
//  - exposed-path probes (.git, database dumps, credential files)
//  - the shipped bundle audit (D6 source maps, D7 secrets in public JS)
// Both take the same single input and hit the same host, so they share a pass
// and a source label. Findings persist into deep_findings (source='exposed-path')
// and flow into the dashboard fix list, the agent brief, MCP, and the Verified
// report counts with no extra wiring.
//
// ARCHIVING: this pass archives findings that no longer reproduce, which it did
// not used to do. That omission mattered most for exactly these checks. A D7
// finding's entire instruction is "rotate this key" — if the finding survived
// the rotation, we'd keep showing CRITICAL after the customer did the one thing
// we asked, and the weekly digest would keep counting it. A check that can't say
// "fixed" is worse than no check: it teaches people that our findings don't
// track reality.
export async function runExposedPathScan(
  userId: string,
  appUrl: string
): Promise<{ total: number; newCount: number; resolvedCount: number; newFindings: ExposedFinding[] }> {
  // Independent: a failure in one must not cost us the other's findings. Both
  // are already best-effort internally and resolve to [] on network trouble.
  const [paths, bundle] = await Promise.all([
    probeExposedPaths(appUrl).catch(() => []),
    auditShippedBundle(appUrl).catch(() => []),
  ]);
  const findings = [...paths, ...bundle];

  const admin = getSupabaseAdmin();
  const nowIso = new Date().toISOString();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "exposed-path")
    .is("archived_at", null);
  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  // Resolved: was open, doesn't reproduce now.
  const resolved = [...active].filter((id) => !current.has(id));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: nowIso })
      .eq("user_id", userId)
      .eq("source", "exposed-path")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "exposed-path",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: f.consequence,
      }))
    );
  }

  // fresh is returned so the caller can alert on it. A newly-shipped
  // service-role key is the most alert-worthy event this product can detect;
  // leaving it to the weekly digest would mean up to seven days of exposure
  // after we already knew.
  return { total: findings.length, newCount: fresh.length, resolvedCount: resolved.length, newFindings: fresh };
}

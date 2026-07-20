import { getSupabaseAdmin } from "@/lib/supabase";
import { probeExposedPaths } from "./exposedPaths";

// Runs the exposed-path probes against a customer's app URL and persists only
// NEW findings into deep_findings (source='exposed-path'), same only-new
// contract as runGithubScan — so they flow into the dashboard fix list, the
// agent brief, MCP, and the Verified report counts with no extra wiring.
export async function runExposedPathScan(
  userId: string,
  appUrl: string
): Promise<{ total: number; newCount: number }> {
  const findings = await probeExposedPaths(appUrl);
  const admin = getSupabaseAdmin();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "exposed-path")
    .is("archived_at", null);
  const active = new Set((existing ?? []).map((r) => r.finding_id as string));

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
  return { total: findings.length, newCount: fresh.length };
}

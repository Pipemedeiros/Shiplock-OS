import { getSupabaseAdmin } from "@/lib/supabase";
import { getLatestScan } from "@/lib/scanHistory";
import { slug } from "./content";
import type { FixableFinding, FindingSource } from "./lane";
import type { FullIssue, Severity } from "@/lib/types";

// Single source of truth for the open, fixable findings of a user — scan
// findings (full_issues, paid-gated content) + deep findings (GitHub source,
// RLS policy, injection). Dependency findings are excluded (applied via the
// GitHub panel's bulk PR). Used by the dashboard fix list AND the MCP endpoints
// so both see exactly the same set. CALLER must have verified the user is paid
// (full_issues is paywalled content).
export async function getFixFindings(userId: string): Promise<FixableFinding[]> {
  const out: FixableFinding[] = [];

  const latest = await getLatestScan(userId);
  for (const iss of (latest?.full_issues ?? []) as FullIssue[]) {
    if (!iss.fix) continue;
    out.push({
      id: `scan:${slug(iss.title)}`, source: "scan", title: iss.title,
      severity: iss.severity, fix: iss.fix, filePath: iss.codefix?.file,
    });
  }

  const { data: deep } = await getSupabaseAdmin()
    .from("deep_findings")
    .select("finding_id, title, severity, consequence")
    .eq("user_id", userId)
    .is("archived_at", null)
    .order("detected_at", { ascending: false })
    .limit(50);
  for (const d of (deep ?? []) as Array<{ finding_id: string; title: string; severity: Severity; consequence: string }>) {
    if (d.finding_id.includes("github:dep:")) continue; // deps → GitHub panel bulk PR
    // Only ever consumed as `!== "scan"` today, but kept accurate so a future
    // per-source grouping doesn't file a DNS record under "GitHub".
    const src: FindingSource = d.finding_id.startsWith("path:")
      ? "graph"
      : d.finding_id.startsWith("policy:")
      ? "policy"
      : d.finding_id.startsWith("advisor:")
        ? "advisor"
        : d.finding_id.startsWith("email_auth:")
          ? "dns"
          : d.finding_id.startsWith("auth_redirect:") || d.finding_id.startsWith("auth_site_url:")
            ? "auth-config"
            : d.finding_id.startsWith("exposed:") || d.finding_id.startsWith("bundle:")
              ? "app"
              : "github";
    out.push({ id: d.finding_id, source: src, title: d.title, severity: d.severity, fix: d.consequence });
  }

  return out;
}

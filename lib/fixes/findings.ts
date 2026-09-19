import { getSupabaseAdmin } from "@/lib/supabase";
import { getLatestScan } from "@/lib/scanHistory";
import { slug } from "./content";
import type { FixableFinding, FindingSource } from "./lane";
import type { FullIssue, Severity } from "@/lib/types";
import { loadReachabilityIndex } from "@/lib/graph/graphRun";
import { triageByReachability } from "@/lib/graph/reachability";

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
    .select("finding_id, title, severity, consequence, source, correlation")
    .eq("user_id", userId)
    .is("archived_at", null)
    .order("detected_at", { ascending: false })
    .limit(50);
  for (const d of (deep ?? []) as Array<{ finding_id: string; title: string; severity: Severity; consequence: string; source: string; correlation?: { surfaces: string[]; proven?: boolean } | null }>) {
    // Dependency findings from the SOURCE scan are shown in the GitHub panel's
    // bulk PR instead. Scoped to source='github' deliberately: zero-day findings
    // reuse the same `github:dep:` id shape (they are the same class of problem,
    // found on a schedule rather than on a push) but the GitHub panel filters on
    // source='github', so skipping them here made them invisible everywhere —
    // written to the database and shown on no screen.
    if (d.source === "github" && d.finding_id.includes("github:dep:")) continue;
    // Only ever consumed as `!== "scan"` today, but kept accurate so a future
    // per-source grouping doesn't file a DNS record under "GitHub".
    const src: FindingSource = d.finding_id.startsWith("traffic:")
      ? "runtime"
      : d.finding_id.startsWith("origin:")
        ? "dns"
        : d.finding_id.startsWith("proven:")
      ? "proven"
      : d.finding_id.startsWith("runtime:")
      ? "runtime"
      : d.finding_id.startsWith("path:")
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
    out.push({
      id: d.finding_id,
      source: src,
      title: d.title,
      severity: d.severity,
      fix: d.consequence,
      ...(d.correlation ? { correlation: d.correlation } : {}),
    });
  }

  // C6 reachability triage. Admitted repository snapshots can promote observed
  // source paths, but bounded coverage never demotes an unobserved path and
  // does not establish current deployment or a database/provider binding.
  //
  // Nothing is ever removed — triageByReachability returns exactly what it was
  // given — and if the source collector has not run, every verdict is `unknown`
  // and the original severity ordering stands. Fail-soft: a triage failure must
  // never cost the customer their finding list.
  try {
    const index = await loadReachabilityIndex(userId);
    return triageByReachability(out, index).map((t) => t.finding);
  } catch (err) {
    console.error("[findings] reachability triage failed:", err instanceof Error ? err.message : err);
    return out;
  }
}

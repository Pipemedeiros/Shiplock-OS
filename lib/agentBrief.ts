import type { LatestScan } from "@/lib/scanHistory";
import type { FullIssue, Severity } from "@/lib/types";

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };

// Paid-only, server-side only — the caller (app/(d)/dashboard/page.tsx) is
// responsible for only invoking this when isPaid && latest, since
// full_issues (fix/codefix) is the exact data the paywall protects. This
// function does no auth/paywall checking itself; it's a pure formatter.
// Deep findings (GitHub source, RLS policy, injection) surfaced from
// deep_findings — title/severity/consequence only, same preview-safe shape.
export interface DeepBriefFinding {
  title: string;
  severity: Severity;
  consequence: string;
}

export function buildAgentBrief(scan: LatestScan, deepFindings: DeepBriefFinding[] = []): string {
  const issues = (scan.full_issues ?? []) as FullIssue[];
  const sorted = [...issues].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  const date = scan.created_at ? new Date(scan.created_at).toISOString() : "unknown";

  const lines: string[] = [];

  lines.push("# ShipLock security brief");
  lines.push("");
  lines.push(
    `Generated ${date} · ${issues.length} open finding${issues.length === 1 ? "" : "s"}` +
      (scan.project_url_hash ? ` · project ...${scan.project_url_hash.slice(-6)}` : "")
  );
  lines.push("");
  lines.push(
    "ShipLock is a continuous security scanner for Supabase-backed apps. This brief lists " +
      "every open finding from the customer's latest audit, with the fix ShipLock recommends " +
      "for each — paste this whole file to your coding agent (Cursor, Lovable, Bolt, v0, or " +
      "similar) and ask it to work through the findings below."
  );
  lines.push("");
  lines.push("## Instructions for the agent");
  lines.push("");
  lines.push(
    "- Apply the fix described for each finding below, using the exact SQL or code shown."
  );
  lines.push(
    "- Do NOT auto-modify Row Level Security policies, auth configuration, or run destructive " +
      "database migrations without stopping to flag the change for human review first. " +
      "These stay copy-paste-and-verify, never silent auto-apply — ask before proceeding on " +
      "anything under those three categories, even if a fix below includes SQL for one."
  );
  lines.push(
    "- After applying a fix, tell the developer what changed and that they should re-run the " +
      "ShipLock scan to confirm it resolved, rather than assuming success."
  );
  lines.push("");

  if (issues.length === 0 && deepFindings.length === 0) {
    lines.push("## Findings");
    lines.push("");
    lines.push("No open findings on the latest scan. Nothing for the agent to do here.");
    return lines.join("\n");
  }

  lines.push("## Database & configuration findings");
  lines.push("");
  if (issues.length === 0) {
    lines.push("No open database/configuration findings on the latest scan.");
    lines.push("");
  }

  for (const issue of sorted) {
    lines.push(`### [${issue.severity}] ${issue.title}`);
    lines.push("");
    lines.push(`**Why it matters:** ${issue.consequence}`);
    lines.push("");
    lines.push(`**Fix:** ${issue.fix}`);
    if (issue.codefix) {
      lines.push("");
      lines.push(`**File:** \`${issue.codefix.file}\` — ${issue.codefix.description}`);
      lines.push("");
      lines.push("```");
      lines.push(issue.codefix.prompt);
      lines.push("```");
    }
    lines.push("");
  }

  // Source & deep findings (GitHub secrets/deps, RLS policy logic, injection).
  if (deepFindings.length > 0) {
    const deepSorted = [...deepFindings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    lines.push("## Source code & deep findings");
    lines.push("");
    lines.push(
      "From your connected repository and deeper analysis. Apply the described fix; the same " +
        "RLS/auth/destructive guardrail above applies — flag those for review, never silent auto-apply."
    );
    lines.push("");
    for (const d of deepSorted) {
      lines.push(`### [${d.severity}] ${d.title}`);
      lines.push("");
      lines.push(`**What to do:** ${d.consequence}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

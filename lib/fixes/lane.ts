import type { Severity } from "@/lib/types";

// Classifies each finding into how its fix gets applied. Every fix is a button;
// the button's action depends on how dangerous the fix is. DB/RLS never applies
// silently — it goes through a reviewable migration PR the customer merges.
// Pure + unit-tested.

export type FixMethod =
  | "migration-pr" // DB/RLS/policy → new migration file in a PR the customer merges
  | "dep-pr" // dependency bump PR (existing githubFix flow)
  | "code-pr" // templatable code edit (headers, secret removal) in a PR
  | "draft-pr" // logic fix (injection/XSS/crypto) → draft PR the human/agent finalizes
  | "deep-link"; // can't be a PR (Supabase dashboard toggle, secret rotation)

export type FindingSource = "scan" | "github" | "policy" | "advisor";

export interface FixableFinding {
  id: string; // finding_id (deep) or a stable scan-issue key
  source: FindingSource;
  title: string;
  severity: Severity;
  fix: string; // fix text / SQL / instructions we already generate
  filePath?: string; // repo file (source findings) or codefix.file (scan)
}

export interface FixLane {
  method: FixMethod;
  label: string; // button label
  editable: boolean; // show the editable preview
  external?: "supabase" | "provider"; // deep-link target class
}

// SQL that belongs in a migration.
const SQL_RE = /\b(alter table|create policy|alter policy|drop policy|enable row level security|revoke|grant)\b/i;
// Fixes that are a dashboard toggle or a manual provider action, not code/SQL.
const DASHBOARD_RE = /(supabase\s*(→|->|\bdashboard\b|\bproject settings\b)|rotate|configure your hosting|password settings|jwt settings|authentication →)/i;

function lane(method: FixMethod, label: string, editable: boolean, external?: FixLane["external"]): FixLane {
  return { method, label, editable, external };
}

export function fixLane(f: FixableFinding): FixLane {
  const id = f.id.toLowerCase();

  // ── Deep (GitHub source) findings — routed by the stable id prefix. ──
  if (id.startsWith("github:dep:")) return lane("dep-pr", "Open fix PR", false);
  if (
    id.startsWith("github:injection:") ||
    id.startsWith("github:xss_sink:") ||
    id.startsWith("github:weak_hash:") ||
    id.startsWith("github:insecure_random:") ||
    id.startsWith("github:secret_in_url:") ||
    id.startsWith("github:token_storage")
  ) {
    return lane("draft-pr", "Open draft fix PR", true);
  }
  if (
    id.startsWith("github:secret:") ||
    id.startsWith("github:committed_env") ||
    id.startsWith("github:logged_secret")
  ) {
    // Remove the reference in a PR; rotation is still a manual provider step
    // (surfaced in the fix text). Editable so the user can adjust the removal.
    return lane("code-pr", "Open fix PR", true);
  }

  // ── Exposed-path findings → a fix-request PR (remove the file / block the
  // path at the host; rotate anything leaked). Not a silent change. ──
  if (id.startsWith("exposed:")) return lane("code-pr", "Open fix PR", true);

  // ── RLS policy-logic findings → migration PR. ──
  if (id.startsWith("policy:")) return lane("migration-pr", "Open migration PR", true);

  // ── Supabase advisors → dashboard vs migration. ──
  if (id.startsWith("advisor:")) {
    if (/auth_leaked_password|jwt|function_search_path/.test(id)) return lane("deep-link", "Open in Supabase", false, "supabase");
    return lane("migration-pr", "Open migration PR", true);
  }

  // ── Scan (Supabase config) findings — classify by the fix content. ──
  if (SQL_RE.test(f.fix)) return lane("migration-pr", "Open migration PR", true);
  if (DASHBOARD_RE.test(f.fix)) {
    const provider = /rotate/i.test(f.fix) && !/supabase/i.test(f.fix);
    return lane("deep-link", provider ? "Rotate secret" : "Open in Supabase", false, provider ? "provider" : "supabase");
  }

  // Fallback: treat as a code PR the user reviews (safest reviewable default).
  return lane("code-pr", "Open fix PR", true);
}

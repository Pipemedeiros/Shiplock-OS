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

/**
 * Every finding source, as a runtime value.
 *
 * A const array with the type derived FROM it, rather than a hand-written union
 * plus a hand-written validator somewhere else. /api/deep/fix used to keep its
 * own Zod enum listing four of these, and it silently drifted: `graph` and
 * `proven` findings route to real PR lanes (lane.ts routes `path:` to draft-pr
 * and `proven:` to migration-pr), so clicking "Open fix PR" on a correlated
 * attack path — the product's whole differentiator — failed validation and
 * returned "Invalid request." Deriving one from the other makes that drift a
 * compile error instead of a dead button.
 */
export const FINDING_SOURCES = [
  "scan", // the 16-check Supabase config scan
  "github", // repo source analysis
  "policy", // our own RLS policy detector
  "advisor", // Supabase's security advisor lints
  "app", // the live app surface: exposed paths, bundle audit
  "dns", // email authentication records
  "auth-config", // Supabase auth URL configuration
  "graph", // a correlated attack path spanning several collectors
  "runtime", // a live attack observed in the auth audit log
  "proven", // demonstrated in a sandboxed replica, not inferred
] as const;

export type FindingSource = (typeof FINDING_SOURCES)[number];

export interface FixableFinding {
  id: string; // finding_id (deep) or a stable scan-issue key
  source: FindingSource;
  title: string;
  severity: Severity;
  fix: string; // fix text / SQL / instructions we already generate
  filePath?: string; // repo file (source findings) or codefix.file (scan)
  /**
   * Which collectors independently confirmed this, for the agreement strip.
   * Only graph-sourced findings carry it — a dependency CVE has one surface by
   * nature, and showing an almost-empty strip there would imply weakness where
   * there is none.
   */
  correlation?: { surfaces: string[]; proven?: boolean };
}

export interface FixLane {
  method: FixMethod;
  label: string; // button label
  editable: boolean; // show the editable preview
  /**
   * True when the PR will contain an edited copy of the customer's own files
   * rather than a description of the change. Set by the caller from
   * hasCodemod(), not decided here — the lane is about HOW a fix applies, the
   * codemod is about whether we can write it.
   */
  appliesRealDiff?: boolean;
  external?: "supabase" | "provider" | "github" | "dns"; // deep-link target class
}

// SQL that belongs in a migration.
const SQL_RE = /\b(alter table|create policy|alter policy|drop policy|enable row level security|revoke|grant)\b/i;
// Fixes that are a dashboard toggle or a manual provider action, not code/SQL.
const DASHBOARD_RE = /(supabase\s*(→|->|\bdashboard\b|\bproject settings\b)|rotate|configure your hosting|password settings|jwt settings|authentication →)/i;

function lane(method: FixMethod, label: string, editable: boolean, external?: FixLane["external"]): FixLane {
  return { method, label, editable, external };
}

/**
 * Strips the `owner/name::` namespace that lib/deep/githubRun.ts prepends to
 * every source finding id.
 *
 * This existed as a live bug: every rule below matched on `github:…`, but real
 * ids arrive as `acme/app::github:…`, so NONE of them ever matched and every
 * GitHub source finding fell through to the code-pr fallback. The consequences
 * were not cosmetic — dependency bumps lost their automated non-editable lane,
 * and injection/XSS/crypto findings were routed to an ordinary fix PR instead of
 * a DRAFT one, which contradicts the rule in AGENTS.md that application logic is
 * never machine-authored.
 */
export function stripRepoNamespace(id: string): string {
  const sep = id.indexOf("::");
  if (sep === -1) return id;
  const prefix = id.slice(0, sep);
  return /^[\w.-]+\/[\w.-]+$/.test(prefix) ? id.slice(sep + 2) : id;
}

export function fixLane(f: FixableFinding): FixLane {
  const id = stripRepoNamespace(f.id.toLowerCase());

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

  // ── A server-only secret reachable from browser code. Not templatable: the
  // fix is deciding WHERE the server-side work should live, which is a judgement
  // about the app's architecture. Draft PR for the human or their agent. ──
  if (id.startsWith("github:client_server_secret:")) {
    return lane("draft-pr", "Open draft fix PR", true);
  }

  // ── A secret behind a public prefix. Renaming the variable is the easy half;
  // the load-bearing half is rotating the key, and it must not look like a code
  // change that finishes the job. ──
  if (id.startsWith("github:public_prefixed_secret")) {
    return lane("deep-link", "Rotate secret", false, "provider");
  }

  // ── Repo visibility. There is no PR that can change this — it is a setting in
  // GitHub, and when credentials are involved the first action is rotation. ──
  if (id.startsWith("github:repo_public")) {
    return lane("deep-link", "Open repo settings", false, "github");
  }

  // ── Exposed-path findings → a fix-request PR (remove the file / block the
  // path at the host; rotate anything leaked). Not a silent change. ──
  if (id.startsWith("exposed:")) return lane("code-pr", "Open fix PR", true);

  // ── Bundle audit. A shipped secret is a rotation, full stop: the key is
  // already public and no code change un-publishes it. Source maps ARE a code
  // change (a build-config flag). ──
  if (id.startsWith("bundle:shipped_secret:")) {
    return lane("deep-link", "Rotate secret", false, "provider");
  }
  if (id.startsWith("bundle:source_map_exposed")) {
    return lane("code-pr", "Open fix PR", true);
  }

  // ── Email authentication is DNS. Not code, not SQL, and not something we can
  // deep-link to, because we don't know who runs their DNS. Honest label. ──
  // ── A secret in history is a rotation and NOTHING else. The code is already
  // correct — that is precisely why it gets missed — so a PR would be actively
  // misleading. ──
  if (id.startsWith("github:history_secret:")) return lane("deep-link", "Rotate secret", false, "provider");

  // ── A flood in progress is not a code defect. We have already acted; what is
  // left is operational. ──
  if (id.startsWith("traffic:")) return lane("deep-link", "Open traffic panel", false, "supabase");

  // ── Origin exposure is a DNS or host firewall change. No PR, and no page
  // we can link to — we do not know who fronts their app. ──
  if (id.startsWith("origin:")) return lane("deep-link", "Show what to change", false, "dns");

  if (id.startsWith("email_auth:")) {
    return lane("deep-link", "Show DNS record", false, "dns");
  }

  // ── Auth URL configuration → the Supabase dashboard page that owns it. ──
  if (id.startsWith("auth_redirect:") || id.startsWith("auth_site_url:")) {
    return lane("deep-link", "Open in Supabase", false, "supabase");
  }

  // ── Attack paths. A path is a CHAIN, and it breaks if any single step is
  // fixed — so there is no one artefact to generate. The evidence already names
  // each step and the two places to cut it; forcing this into a single PR would
  // pick one arbitrarily and hide the choice from the person best placed to make
  // it. Draft PR keeps the decision with them, with the reasoning attached. ──
  if (id.startsWith("path:")) return lane("draft-pr", "Open draft fix PR", true);

  // ── A newly-published CVE in an existing dependency is still a dependency
  // bump: same automated, non-editable lane as github:dep. ──
  if (id.startsWith("github:dep:") || /^zero-?day:/.test(id)) return lane("dep-pr", "Open fix PR", false);

  // ── A proven tenant-isolation failure has a specific, known fix: a policy
  // comparing the owner column to auth.uid(). Migration PR. ──
  if (id.startsWith("proven:")) return lane("migration-pr", "Open migration PR", true);

  // ── A live attack is not a code defect. There is no PR that makes it stop;
  // the actions are operational (reset a session, enable rate limiting, require
  // a second factor), so we deep-link to the auth settings rather than pretend a
  // diff would help. ──
  if (id.startsWith("runtime:")) return lane("deep-link", "Open in Supabase", false, "supabase");

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

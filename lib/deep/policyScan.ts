// Supabase RLS policy-logic detector — closes the #1 coverage gap
// (ROADMAP.md): the external anon-key scan sees "RLS enabled = good" but
// cannot read policy LOGIC, so a table with RLS on but a broken policy passes as
// safe. This reads the actual policy definitions (pg_policies, via the read-only
// Management API) and flags the permissive/bypassable ones — the single most
// common real Supabase critical.
//
// PURE. No network, no credential. Takes already-fetched policy rows + Supabase's
// own security advisors and returns findings in the shared GithubFinding shape
// (id/severity/title/consequence) so they persist into deep_findings unchanged.
//
// Conservative by design (same FP/FN discipline as the reasoning pass): only the
// KNOWN-BAD patterns are flagged, never a generic "no uid reference" heuristic
// that would false-positive on legitimately-public tables (e.g. published content).
import type { Severity } from "@/lib/types";
import type { GithubFinding } from "./githubScan";

// A row from `SELECT schemaname, tablename, policyname, cmd, qual, with_check, roles FROM pg_policies`.
export interface PgPolicy {
  schemaname: string;
  tablename: string;
  policyname: string;
  cmd: string; // SELECT | INSERT | UPDATE | DELETE | ALL
  qual: string | null; // USING expression (null for INSERT)
  with_check: string | null; // WITH CHECK expression (null unless INSERT/UPDATE/ALL)
  roles: string[]; // e.g. ["authenticated"], ["public"], ["anon","authenticated"]
}

// A security lint from the Supabase Management API `/advisors/security`
// (equivalently the get_advisors tool). Fields defensive/optional — the exact
// shape varies by Supabase version.
export interface SupabaseAdvisor {
  name?: string; // e.g. "rls_enabled_no_policy", "permissive_rls_policy"
  title?: string;
  level?: string; // ERROR | WARN | INFO
  description?: string;
  detail?: string;
  cache_key?: string;
  remediation?: string;
  metadata?: { name?: string; schema?: string; type?: string } | null;
}

const WRITE_CMDS = new Set(["INSERT", "UPDATE", "DELETE", "ALL"]);
// Roles that make a policy reachable by an untrusted client. service_role /
// custom roles are not client-reachable, so their policies are not an exposure.
const CLIENT_ROLES = new Set(["anon", "authenticated", "public"]);

const norm = (e: string | null | undefined): string =>
  (e ?? "").toLowerCase().replace(/::\w+/g, "").replace(/\s+/g, " ").trim();

const isTrue = (e: string): boolean => e === "true" || e === "(true)";
const referencesUid = (e: string): boolean =>
  e.includes("auth.uid()") || e.includes("->> 'sub'") || e.includes("->>'sub'");
// Gated purely on "is this a logged-in user", with no per-row/user scoping.
const roleOnlyGate = (e: string): boolean =>
  (e.includes("auth.role()") || e.includes("current_setting('role'")) && !referencesUid(e);
// References data the user can edit about themselves — bypassable.
const referencesUserMetadata = (e: string): boolean =>
  e.includes("user_metadata") || e.includes("raw_user_meta_data");

function clientReachable(roles: string[]): boolean {
  return roles.some((r) => CLIENT_ROLES.has(r.toLowerCase()));
}

function pushCritical(
  out: GithubFinding[], p: PgPolicy, reason: string, title: string, consequence: string, severity: Severity = "CRITICAL"
) {
  out.push({
    id: `policy:${p.schemaname}.${p.tablename}:${p.policyname}:${reason}`,
    severity, title, consequence,
    packageName: null, version: null, vulnId: null, cveId: null,
  });
}

/**
 * Analyze pg_policies rows for permissive / bypassable RLS. One finding per
 * distinct issue, stable-id'd by table+policy+reason.
 */
export function analyzePolicies(policies: PgPolicy[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const p of policies) {
    if (p.schemaname !== "public") continue; // only user-facing schema
    if (!clientReachable(p.roles)) continue; // service_role-only = not an exposure

    const isWrite = WRITE_CMDS.has(p.cmd.toUpperCase());
    const using = norm(p.qual);
    const check = norm(p.with_check);
    const anonFacing = p.roles.some((r) => ["anon", "public"].includes(r.toLowerCase()));
    const who = anonFacing ? "any visitor (even signed-out)" : "any logged-in user";

    // Rule A — unrestricted (USING (true) / WITH CHECK (true)).
    const readTrue = using !== "" && isTrue(using);
    const writeTrue = check !== "" && isTrue(check);
    if (isWrite && (writeTrue || (using !== "" && isTrue(using)))) {
      pushCritical(out, p, "unrestricted_write",
        `RLS policy "${p.policyname}" allows unrestricted writes to ${p.tablename}`,
        `The policy's check is \`true\`, so ${who} can insert/update/delete any row in "${p.tablename}". ` +
        `Scope it to the owner, e.g. WITH CHECK (auth.uid() = user_id).`);
    } else if (!isWrite && readTrue) {
      pushCritical(out, p, "unrestricted_read",
        `RLS policy "${p.policyname}" exposes every row of ${p.tablename}`,
        `The policy's USING clause is \`true\`, so ${who} can read every row in "${p.tablename}". ` +
        `If this table isn't meant to be fully public, scope it, e.g. USING (auth.uid() = user_id).`);
    }
    // Rule B — role-only gate (logged-in, but no per-user scoping). The classic
    // USING (auth.role() = 'authenticated'): any authenticated user reads ALL rows.
    else if (roleOnlyGate(isWrite ? (check || using) : using)) {
      pushCritical(out, p, "role_only_gate",
        `RLS policy "${p.policyname}" on ${p.tablename} checks login status, not ownership`,
        `The policy only verifies the request is authenticated (e.g. auth.role() = 'authenticated') ` +
        `with no per-user scoping, so any logged-in user can ${isWrite ? "modify" : "read"} every row in "${p.tablename}". ` +
        `Add ownership scoping, e.g. auth.uid() = user_id.`);
    }

    // Rule C — trusts user-modifiable metadata (independent; can co-exist).
    if (referencesUserMetadata(using) || referencesUserMetadata(check)) {
      pushCritical(out, p, "user_metadata_trust",
        `RLS policy "${p.policyname}" on ${p.tablename} trusts user-editable metadata`,
        `The policy reads user_metadata / raw_user_meta_data, which a user can change about themselves ` +
        `(e.g. via updateUser). A check like user_metadata->>'role' = 'admin' is bypassable. ` +
        `Use app_metadata (server-controlled) or a server-owned column instead.`,
        "WARNING");
    }
  }

  return out;
}

const LEVEL_TO_SEVERITY: Record<string, Severity> = { ERROR: "CRITICAL", WARN: "WARNING", INFO: "INFO" };
// Security lints worth surfacing to a non-technical founder (avoid noise).
// DELIBERATELY EXCLUDES `rls_enabled_no_policy` (0008): RLS enabled + zero
// policies = deny-all, which is the SECURE service-role-only pattern (ShipLock's
// own internal tables use it on purpose). It's an INFO ambiguity, not an
// exposure — surfacing it would fire a false positive on every locked-down
// table. The lints below are genuine exposures / bypasses.
const SECURITY_LINTS = new Set([
  "rls_disabled_in_public", "policy_exists_rls_disabled",
  "permissive_rls_policy", "rls_references_user_metadata", "security_definer_view",
  "function_search_path_mutable", "auth_users_exposed", "exposed_sensitive_data",
  "auth_leaked_password_protection",
]);

/**
 * Map Supabase's own security advisors into findings. These are computed by
 * Supabase (free to consume) and cover checks our external scan can't — we lean
 * on them rather than re-deriving. Non-security / unknown lints are dropped.
 */
export function mapAdvisors(advisors: SupabaseAdvisor[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  for (const a of advisors) {
    if (!a.name || !SECURITY_LINTS.has(a.name)) continue;
    const severity = LEVEL_TO_SEVERITY[(a.level ?? "WARN").toUpperCase()] ?? "WARNING";
    const target = a.metadata?.name ? ` (${a.metadata.schema ?? "public"}.${a.metadata.name})` : "";
    out.push({
      id: `advisor:${a.name}:${a.cache_key ?? a.metadata?.name ?? "global"}`,
      severity,
      title: (a.title ?? a.name) + target,
      consequence: [a.detail, a.description, a.remediation].filter(Boolean).join(" ") ||
        "Supabase's security advisor flagged this configuration.",
      packageName: null, version: null, vulnId: null, cveId: null,
    });
  }
  return out;
}

/**
 * Merge policy findings with advisor findings, dropping advisor rows that
 * duplicate a policy finding for the same table (our policy finding is more
 * specific — it names the policy + the fix). Policy findings win.
 */
export function mergePolicyFindings(policyFindings: GithubFinding[], advisorFindings: GithubFinding[]): GithubFinding[] {
  const RLS_ADVISORS = new Set(["permissive_rls_policy", "rls_references_user_metadata"]);
  const coveredTables = new Set(
    policyFindings.map((f) => f.id.split(":")[1]) // "policy:public.table:..." -> "public.table"
  );
  const kept = advisorFindings.filter((f) => {
    const lintName = f.id.split(":")[1];
    if (!RLS_ADVISORS.has(lintName)) return true; // non-overlapping advisor, keep
    // overlapping advisor: drop if any policy finding already covers a table.
    // (advisor ids don't carry the schema.table, so a coarse guard: if we have
    // ANY policy finding, prefer it for the RLS-permissive class.)
    return coveredTables.size === 0;
  });
  return [...policyFindings, ...kept];
}

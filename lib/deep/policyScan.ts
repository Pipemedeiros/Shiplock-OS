// Supabase RLS policy-logic detector — closes the #1 coverage gap
// (AGENTS.md): the external anon-key scan sees "RLS enabled = good" but
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

// Slugs verified against github.com/supabase/splinter/lints on 2026-07-29.
//
// This used to be an ALLOWLIST of nine names, which silently dropped anything it
// didn't recognise — and two of its nine entries were wrong, so they never
// matched at all: `permissive_rls_policy` (really `rls_policy_always_true`) and
// `exposed_sensitive_data` (really `sensitive_columns_exposed`). The first of
// those is the `USING (true)` case — the single most important lint Supabase
// emits — and we were discarding it.
//
// Inverted to a deny-list. We call the /advisors/security endpoint, so Supabase
// has already decided these are security lints; second-guessing that with a
// hand-maintained allowlist buys nothing and loses every rule they add. Rule
// 0030 will now surface on the day it ships.

// Performance and operational lints. Excluded because they are not security
// findings, and for this ICP any non-actionable alert is pure triage burden.
const NON_SECURITY_LINTS = new Set([
  "unindexed_foreign_keys", // 0001
  "auth_rls_initplan", // 0003
  "no_primary_key", // 0004
  "unused_index", // 0005
  "multiple_permissive_policies", // 0006 — perf, not exposure
  "duplicate_index", // 0009
  "unsupported_reg_types", // 0018
  "table_bloat", // 0020
  "fkey_to_auth_unique", // 0021
]);

// Excluded for a DIFFERENT reason: this is a SECURE state that Supabase reports
// as INFO. RLS enabled with zero policies is deny-all — the correct
// service-role-only pattern, which ShipLock's own internal tables use on
// purpose. Surfacing it would fire on every properly locked-down table.
const SECURE_STATE_LINTS = new Set(["rls_enabled_no_policy"]); // 0008

// Where Supabase's generic level understates the risk FOR THIS ICP. Their level
// is calibrated for all Postgres users; ours is calibrated for a multi-tenant
// SaaS holding customer data.
const SEVERITY_OVERRIDE: Record<string, Severity> = {
  // 0007 — Supabase says INFO. But policies written while RLS is OFF is the
  // worst state there is: the developer believes the table is protected, the
  // policies are inert, and the table is fully readable.
  policy_exists_rls_disabled: "CRITICAL",
  // 0024 — Supabase says WARN. `USING (true)` means every signed-in user reads
  // every row in a multi-tenant app.
  rls_policy_always_true: "CRITICAL",
  // 0019 — an exposed queue is a write primitive, not just a read.
  insecure_queue_exposed_in_api: "CRITICAL",
};

// Consequence in the founder's language. Supabase's remediation text is written
// for a Postgres engineer; per the voice rules we lead with what it costs, not
// with the mechanism. Falls back to Supabase's own text when we have nothing
// better to say.
const CONSEQUENCE: Record<string, string> = {
  policy_exists_rls_disabled:
    "This table has access policies written for it, but row-level security is switched off, so none of them apply. Anyone with your public key can read every row, and the policies give a false impression that the table is protected.",
  rls_policy_always_true:
    "The policy on this table allows unrestricted access, so every signed-in user can read every row, including other customers' data. Signing up is enough to see everything.",
  rls_disabled_in_public:
    "This table is reachable through your public API with no access rules at all. Anyone who has your publishable key (which your own frontend ships to every visitor) can read it.",
  sensitive_columns_exposed:
    "Columns that look like personal or sensitive data are reachable through your public API.",
  auth_users_exposed:
    "Your authentication user records are reachable through a view in the public API. That exposes emails and account metadata for every user you have.",
  security_definer_view:
    "This view runs with its creator's privileges and bypasses row-level security, so it returns rows the caller should never see.",
  rls_references_user_metadata:
    "This policy trusts user metadata that the user can edit themselves, so a user can change their own metadata to grant themselves access.",
  anon_security_definer_function_executable:
    "This function runs with elevated privileges and can be called by anyone, without signing in.",
  authenticated_security_definer_function_executable:
    "This function runs with elevated privileges and can be called by any signed-in user.",
  insecure_queue_exposed_in_api:
    "This queue is reachable through your public API without protection, so a caller can read or enqueue messages.",
  public_bucket_allows_listing:
    "This storage bucket lets anyone list its contents, so filenames (often revealing in themselves) are public even where the files are not.",
  pg_graphql_anon_table_exposed:
    "This table is queryable over GraphQL by unauthenticated callers.",
  pg_graphql_authenticated_table_exposed:
    "This table is queryable over GraphQL by any signed-in caller.",
  extension_in_public:
    "An extension is installed in the public schema, which widens what is reachable through your API surface.",
  extension_versions_outdated:
    "An installed extension is behind on versions, so it may carry known, already-patched vulnerabilities.",
  materialized_view_in_api: "This materialised view is exposed through your public API.",
  foreign_table_in_api:
    "A foreign table is exposed through your public API. Foreign tables do not enforce row-level security.",
  function_search_path_mutable:
    "This function has a mutable search path, which allows a caller to influence which objects it resolves to.",
};

/**
 * Supabase reports lint names either bare (`rls_policy_always_true`) or with the
 * Splinter number prefix (`0024_rls_policy_always_true`). Normalise so the
 * lookup tables above work either way — getting this wrong is how the previous
 * allowlist silently matched nothing.
 */
export function normaliseLintName(name: string): string {
  return name.trim().toLowerCase().replace(/^\d{4}_/, "");
}

/** Supabase security advisors as findings, skipping performance lints and
 * states that are already secure. */
export function mapAdvisors(advisors: SupabaseAdvisor[]): GithubFinding[] {
  const out: GithubFinding[] = [];
  for (const a of advisors) {
    if (!a.name) continue;
    const lint = normaliseLintName(a.name);
    if (NON_SECURITY_LINTS.has(lint)) continue;
    if (SECURE_STATE_LINTS.has(lint)) continue;

    const severity =
      SEVERITY_OVERRIDE[lint] ??
      LEVEL_TO_SEVERITY[(a.level ?? "WARN").toUpperCase()] ??
      "WARNING";

    const target = a.metadata?.name ? ` (${a.metadata.schema ?? "public"}.${a.metadata.name})` : "";
    const consequence =
      CONSEQUENCE[lint] ??
      [a.detail, a.description, a.remediation].filter(Boolean).join(" ") ??
      "";

    out.push({
      // Stable across passes AND parseable for dedupe: the lint plus the
      // qualified object. Prefer schema.object over Supabase's cache_key so
      // mergePolicyFindings can compare targets with our own policy findings
      // (which key on schema.table). cache_key is the fallback.
      id: `advisor:${lint}:${
        a.metadata?.name
          ? `${a.metadata.schema ?? "public"}.${a.metadata.name}`
          : (a.cache_key ?? "global")
      }`,
      severity,
      title: (a.title ?? lint.replace(/_/g, " ")) + target,
      consequence:
        consequence || "Supabase's security advisor flagged this configuration.",
      packageName: null,
      version: null,
      vulnId: null,
      cveId: null,
    });
  }
  return out;
}

/**
 * Merge policy findings with advisor findings, dropping advisor rows that
 * duplicate a policy finding for the same table (our policy finding is more
 * specific — it names the policy + the fix). Policy findings win.
 */
export function mergePolicyFindings(
  policyFindings: GithubFinding[],
  advisorFindings: GithubFinding[]
): GithubFinding[] {
  // Advisor lints that describe the SAME condition our own policy detector
  // reports. When both fire we keep ours, because ours names the specific policy
  // and carries a fix; the advisor is a duplicate the customer would have to
  // triage.
  //
  // NOTE the slug: `rls_policy_always_true` (0024), not `permissive_rls_policy`.
  // The old name here was wrong, which meant this dedupe never fired — harmless
  // only because mapAdvisors was dropping that lint too. Both are fixed now, so
  // this guard is live for the first time.
  const OVERLAPS_POLICY_DETECTOR = new Set([
    "rls_policy_always_true", // 0024
    "rls_references_user_metadata", // 0015
  ]);

  // "policy:public.orders:policy_name:reason" -> "public.orders"
  const coveredTargets = new Set(policyFindings.map((f) => f.id.split(":")[1]));

  const kept = advisorFindings.filter((f) => {
    const [, lint, target] = f.id.split(":");
    if (!OVERLAPS_POLICY_DETECTOR.has(lint)) return true;
    // Per-OBJECT, not global. The previous version dropped every overlapping
    // advisor as soon as ANY policy finding existed, so a permissive policy on
    // `invoices` was discarded because we happened to find one on `orders`.
    return !coveredTargets.has(target);
  });

  return [...policyFindings, ...kept];
}

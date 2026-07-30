import { describe, expect, it } from "vitest";
import { analyzePolicies, mapAdvisors, mergePolicyFindings, type PgPolicy, type SupabaseAdvisor } from "./policyScan";

const pol = (p: Partial<PgPolicy>): PgPolicy => ({
  schemaname: "public", tablename: "t", policyname: "p", cmd: "SELECT",
  qual: null, with_check: null, roles: ["authenticated"], ...p,
});

describe("analyzePolicies — catches the permissive/bypassable patterns (no false negatives)", () => {
  it("flags USING (true) SELECT as an unrestricted read", () => {
    const f = analyzePolicies([pol({ tablename: "orders", qual: "true", cmd: "SELECT" })]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("CRITICAL");
    expect(f[0].id).toContain("unrestricted_read");
  });

  it("marks an anon/public USING (true) read as visitor-facing", () => {
    const f = analyzePolicies([pol({ tablename: "orders", qual: "true", roles: ["public"] })]);
    expect(f[0].consequence).toContain("any visitor");
  });

  it("flags WITH CHECK (true) writes as unrestricted", () => {
    const f = analyzePolicies([pol({ tablename: "orders", cmd: "INSERT", with_check: "true" })]);
    expect(f[0].id).toContain("unrestricted_write");
    expect(f[0].severity).toBe("CRITICAL");
  });

  it("flags the role-only gate (auth.role() with no ownership scoping)", () => {
    const f = analyzePolicies([pol({ tablename: "orders", qual: "(auth.role() = 'authenticated'::text)" })]);
    expect(f).toHaveLength(1);
    expect(f[0].id).toContain("role_only_gate");
    expect(f[0].severity).toBe("CRITICAL");
  });

  it("flags a policy that trusts user-editable metadata (bypassable admin gate)", () => {
    const f = analyzePolicies([pol({ tablename: "admin_panel", qual: "((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin')" })]);
    expect(f.some((x) => x.id.includes("user_metadata_trust"))).toBe(true);
    expect(f.find((x) => x.id.includes("user_metadata_trust"))?.severity).toBe("WARNING");
  });
});

describe("analyzePolicies — stays quiet on correct policies (no false positives)", () => {
  it("does NOT flag a properly owner-scoped SELECT", () => {
    expect(analyzePolicies([pol({ qual: "(auth.uid() = user_id)" })])).toEqual([]);
  });

  it("does NOT flag an owner-scoped write", () => {
    expect(analyzePolicies([pol({ cmd: "UPDATE", qual: "(auth.uid() = user_id)", with_check: "(auth.uid() = user_id)" })])).toEqual([]);
  });

  it("does NOT flag a legitimately public content table scoped by a column", () => {
    // USING (is_published = true) — public on purpose, but scoped by a server column, not `true`.
    expect(analyzePolicies([pol({ tablename: "posts", qual: "(is_published = true)", roles: ["anon"] })])).toEqual([]);
  });

  it("ignores service_role-only policies (not client-reachable)", () => {
    expect(analyzePolicies([pol({ qual: "true", roles: ["service_role"] })])).toEqual([]);
  });

  it("ignores non-public schemas", () => {
    expect(analyzePolicies([pol({ schemaname: "auth", qual: "true" })])).toEqual([]);
  });
});

describe("mapAdvisors — deny-list, so new Supabase rules surface automatically", () => {
  const adv = (over: Partial<SupabaseAdvisor> = {}): SupabaseAdvisor => ({
    name: "rls_disabled_in_public",
    level: "ERROR",
    cache_key: "k1",
    metadata: { name: "orders", schema: "public" },
    ...over,
  });

  // The regression that motivated the rewrite. The old allowlist held
  // "permissive_rls_policy", but the real Splinter slug is
  // "rls_policy_always_true" — so the single most important lint Supabase emits
  // was silently discarded.
  it("surfaces rls_policy_always_true (0024) — the USING(true) case", () => {
    const f = mapAdvisors([adv({ name: "rls_policy_always_true", level: "WARN" })]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("CRITICAL"); // overridden up from Supabase's WARN
    expect(f[0].consequence).toMatch(/every signed-in user can read every row/i);
  });

  it("surfaces sensitive_columns_exposed (0023) — the other slug the allowlist got wrong", () => {
    expect(mapAdvisors([adv({ name: "sensitive_columns_exposed" })])).toHaveLength(1);
  });

  it("surfaces a lint it has never seen, rather than dropping it", () => {
    const f = mapAdvisors([adv({ name: "some_future_lint_0030", level: "ERROR", detail: "New rule." })]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("CRITICAL");
    expect(f[0].consequence).toBe("New rule."); // falls back to Supabase's text
  });

  it("normalises the Splinter number prefix", () => {
    const bare = mapAdvisors([adv({ name: "rls_policy_always_true", level: "WARN" })]);
    const prefixed = mapAdvisors([adv({ name: "0024_rls_policy_always_true", level: "WARN" })]);
    expect(prefixed).toHaveLength(1);
    expect(prefixed[0].severity).toBe(bare[0].severity);
    expect(prefixed[0].id).toBe(bare[0].id); // same finding, not a duplicate
  });

  it("normalises case and surrounding whitespace", () => {
    expect(mapAdvisors([adv({ name: "  RLS_Policy_Always_True  ", level: "WARN" })])[0].severity).toBe("CRITICAL");
  });

  it("raises policy_exists_rls_disabled (0007) from INFO to CRITICAL", () => {
    // Policies written while RLS is off: the developer believes the table is
    // protected and it is fully readable. Supabase rates this INFO.
    const f = mapAdvisors([adv({ name: "policy_exists_rls_disabled", level: "INFO" })]);
    expect(f[0].severity).toBe("CRITICAL");
    expect(f[0].consequence).toMatch(/false impression/i);
  });

  it("drops performance lints — non-actionable alerts are pure triage burden", () => {
    for (const name of [
      "unindexed_foreign_keys", "auth_rls_initplan", "no_primary_key", "unused_index",
      "multiple_permissive_policies", "duplicate_index", "unsupported_reg_types",
      "table_bloat", "fkey_to_auth_unique",
    ]) {
      expect(mapAdvisors([adv({ name, level: "WARN" })]), name).toEqual([]);
    }
  });

  it("drops rls_enabled_no_policy (0008) — deny-all is the SECURE pattern", () => {
    expect(mapAdvisors([adv({ name: "rls_enabled_no_policy", level: "INFO" })])).toEqual([]);
  });

  it("still drops 0008 when it arrives number-prefixed", () => {
    expect(mapAdvisors([adv({ name: "0008_rls_enabled_no_policy", level: "INFO" })])).toEqual([]);
  });

  it("surfaces leaked-password protection as a WARNING", () => {
    const f = mapAdvisors([adv({ name: "auth_leaked_password_protection", level: "WARN", metadata: null })]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("WARNING");
  });

  it("prefers our consequence text over Supabase's engineer-facing remediation", () => {
    const f = mapAdvisors([adv({ name: "rls_disabled_in_public", detail: "Enable RLS via ALTER TABLE." })]);
    expect(f[0].consequence).toMatch(/publishable key/i);
    expect(f[0].consequence).not.toMatch(/ALTER TABLE/);
  });

  it("names the affected object in the title", () => {
    expect(mapAdvisors([adv()])[0].title).toContain("public.orders");
  });

  it("gives distinct ids to the same lint on different objects", () => {
    const f = mapAdvisors([
      adv({ cache_key: "a", metadata: { name: "orders", schema: "public" } }),
      adv({ cache_key: "b", metadata: { name: "invoices", schema: "public" } }),
    ]);
    expect(new Set(f.map((x) => x.id)).size).toBe(2);
  });

  // Edge cases: the API is experimental and the shape is documented as varying.
  it("survives a missing name, empty list, and absent metadata", () => {
    expect(mapAdvisors([])).toEqual([]);
    expect(mapAdvisors([{ level: "ERROR" }])).toEqual([]);
    expect(mapAdvisors([{ name: "unknown_lint" }])).toHaveLength(1); // level defaults
  });

  it("defaults an unknown level to WARNING rather than throwing", () => {
    expect(mapAdvisors([adv({ name: "unknown_lint", level: "BANANA" })])[0].severity).toBe("WARNING");
  });

  it("never emits an empty consequence", () => {
    const f = mapAdvisors([{ name: "unknown_lint", level: "WARN" }]);
    expect(f[0].consequence.length).toBeGreaterThan(0);
  });
});

describe("mergePolicyFindings — our policy findings win over duplicate advisors", () => {
  const adv = (name: string, table: string, schema = "public"): SupabaseAdvisor => ({
    name, level: "ERROR", cache_key: `ck-${name}-${table}`, metadata: { schema, name: table },
  });

  it("drops the rls_policy_always_true advisor when we already reported that table ourselves", () => {
    const policyF = analyzePolicies([pol({ tablename: "orders", qual: "true" })]);
    const merged = mergePolicyFindings(policyF, mapAdvisors([adv("rls_policy_always_true", "orders")]));
    expect(merged.filter((f) => f.id.startsWith("advisor:rls_policy_always_true"))).toHaveLength(0);
    expect(merged.filter((f) => f.id.startsWith("policy:"))).toHaveLength(1);
  });

  // The bug this replaces: dedupe was global, so ANY policy finding suppressed
  // EVERY overlapping advisor. A permissive policy on `orders` silently hid a
  // permissive policy on `invoices` — a false negative in the highest-severity class.
  it("keeps an overlapping advisor for a DIFFERENT table", () => {
    const policyF = analyzePolicies([pol({ tablename: "orders", qual: "true" })]);
    const merged = mergePolicyFindings(policyF, mapAdvisors([adv("rls_policy_always_true", "invoices")]));
    expect(merged.filter((f) => f.id === "advisor:rls_policy_always_true:public.invoices")).toHaveLength(1);
    expect(merged).toHaveLength(2);
  });

  it("dedupes per schema, not just per table name", () => {
    const policyF = analyzePolicies([pol({ schemaname: "public", tablename: "orders", qual: "true" })]);
    const merged = mergePolicyFindings(policyF, mapAdvisors([adv("rls_policy_always_true", "orders", "billing")]));
    expect(merged.filter((f) => f.id.endsWith("billing.orders"))).toHaveLength(1);
  });

  it("also dedupes rls_references_user_metadata against a matching policy finding", () => {
    const policyF = analyzePolicies([
      pol({ tablename: "orders", qual: "(auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'" }),
    ]);
    expect(policyF.length).toBeGreaterThan(0);
    const merged = mergePolicyFindings(policyF, mapAdvisors([adv("rls_references_user_metadata", "orders")]));
    expect(merged.filter((f) => f.id.startsWith("advisor:rls_references_user_metadata"))).toHaveLength(0);
  });

  it("keeps non-overlapping advisors untouched even when policy findings exist", () => {
    const policyF = analyzePolicies([pol({ tablename: "orders", qual: "true" })]);
    const merged = mergePolicyFindings(
      policyF,
      mapAdvisors([adv("security_definer_view", "orders"), adv("policy_exists_rls_disabled", "orders")])
    );
    expect(merged.filter((f) => f.id.startsWith("advisor:"))).toHaveLength(2);
  });

  it("keeps every advisor when we have no policy findings at all", () => {
    const merged = mergePolicyFindings([], mapAdvisors([adv("rls_policy_always_true", "orders")]));
    expect(merged).toHaveLength(1);
  });

  it("handles both sides empty", () => {
    expect(mergePolicyFindings([], [])).toEqual([]);
  });

  it("survives an advisor with no metadata (id falls back to cache_key, never dedupes wrongly)", () => {
    const policyF = analyzePolicies([pol({ tablename: "orders", qual: "true" })]);
    const merged = mergePolicyFindings(policyF, mapAdvisors([
      { name: "rls_policy_always_true", level: "ERROR", cache_key: "orphan" },
    ]));
    expect(merged.filter((f) => f.id === "advisor:rls_policy_always_true:orphan")).toHaveLength(1);
  });
});

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

describe("mapAdvisors — surfaces security lints, drops noise", () => {
  it("maps a permissive_rls_policy ERROR to a CRITICAL finding", () => {
    const advisors: SupabaseAdvisor[] = [
      { name: "permissive_rls_policy", title: "Permissive RLS policy", level: "ERROR", detail: "Table exposes rows", cache_key: "abc", metadata: { name: "orders", schema: "public" } },
    ];
    const f = mapAdvisors(advisors);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("CRITICAL");
    expect(f[0].title).toContain("orders");
  });

  it("drops unknown / non-security lints", () => {
    expect(mapAdvisors([{ name: "unused_index", level: "INFO" }])).toEqual([]);
  });

  it("drops rls_enabled_no_policy (deny-all is the secure service-role-only pattern, not an exposure)", () => {
    expect(mapAdvisors([{ name: "rls_enabled_no_policy", level: "INFO", metadata: { name: "stripe_webhook_events" } }])).toEqual([]);
  });

  it("surfaces leaked-password-protection disabled as a WARNING", () => {
    const f = mapAdvisors([{ name: "auth_leaked_password_protection", level: "WARN", detail: "enable HIBP", cache_key: "z" }]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("WARNING");
  });
});

describe("mergePolicyFindings — policy findings win over overlapping advisors", () => {
  it("drops a permissive_rls_policy advisor when a policy finding exists", () => {
    const policyF = analyzePolicies([pol({ tablename: "orders", qual: "true" })]);
    const advisorF = mapAdvisors([{ name: "permissive_rls_policy", level: "ERROR", cache_key: "x", metadata: { name: "orders" } }]);
    const merged = mergePolicyFindings(policyF, advisorF);
    expect(merged.filter((f) => f.id.startsWith("advisor:permissive_rls_policy"))).toHaveLength(0);
    expect(merged.filter((f) => f.id.startsWith("policy:"))).toHaveLength(1);
  });

  it("keeps non-overlapping advisors (e.g. security_definer_view)", () => {
    const advisorF = mapAdvisors([{ name: "security_definer_view", level: "ERROR", cache_key: "y", metadata: { name: "v" } }]);
    const merged = mergePolicyFindings([], advisorF);
    expect(merged).toHaveLength(1);
  });
});

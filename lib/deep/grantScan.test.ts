import { describe, expect, it } from "vitest";
import { analyzeGrants, GRANT_INVENTORY_SQL, isEntitlementColumn, type ColumnGrant } from "./grantScan";
import { assertReadOnly } from "./supabaseMgmt";

const g = (grantee: string, table: string, column: string, privilege: string): ColumnGrant => ({
  grantee, table, column, privilege,
});

describe("entitlement columns", () => {
  it("recognises columns that decide what a user gets", () => {
    for (const c of ["is_paid", "is_admin", "role", "plan", "credits", "paid_until", "banned"]) {
      expect(isEntitlementColumn(c), c).toBe(true);
    }
  });

  it("does not treat ordinary columns as entitlement", () => {
    for (const c of ["email", "created_at", "title", "amount"]) {
      expect(isEntitlementColumn(c), c).toBe(false);
    }
  });
});

describe("the bug we shipped ourselves (migration 035)", () => {
  // anon + authenticated held SELECT/INSERT/UPDATE on every column of
  // user_profiles, including encrypted tokens and is_paid.
  const ours: ColumnGrant[] = [
    g("authenticated", "user_profiles", "is_paid", "UPDATE"),
    g("authenticated", "user_profiles", "paid_until", "UPDATE"),
    g("authenticated", "user_profiles", "monitored_anon_key_encrypted", "SELECT"),
    g("authenticated", "user_profiles", "supabase_mgmt_token_encrypted", "SELECT"),
    g("authenticated", "user_profiles", "email", "SELECT"),
  ];

  it("would have caught it", () => {
    const out = analyzeGrants(ours);
    expect(out.length).toBeGreaterThan(0);
    expect(out.every((x) => x.severity === "CRITICAL")).toBe(true);
  });

  it("flags the credential columns specifically", () => {
    const cred = analyzeGrants(ours).find((x) => x.id.includes("credential_readable"))!;
    expect(cred.consequence).toContain("monitored_anon_key_encrypted");
    expect(cred.consequence).toContain("supabase_mgmt_token_encrypted");
  });

  it("flags the entitlement columns as a paywall bypass waiting to happen", () => {
    const ent = analyzeGrants(ours).find((x) => x.id.includes("entitlement_writable"))!;
    expect(ent.consequence).toContain("is_paid");
    expect(ent.consequence).toContain("self-serve upgrade");
  });

  // The whole framing: it was NOT exploitable, and that is why it survived review.
  it("says plainly this may not be an active breach", () => {
    const out = analyzeGrants(ours);
    expect(out.some((x) => /not an active breach|nothing is leaking right now/.test(x.consequence))).toBe(true);
  });

  it("explains the dependency between grants and policies", () => {
    const ent = analyzeGrants(ours).find((x) => x.id.includes("entitlement_writable"))!;
    expect(ent.consequence).toContain("users can update their own profile");
  });
});

describe("scope", () => {
  it("ignores roles a browser cannot reach", () => {
    expect(analyzeGrants([g("service_role", "user_profiles", "is_paid", "UPDATE")])).toEqual([]);
    expect(analyzeGrants([g("postgres", "user_profiles", "is_paid", "UPDATE")])).toEqual([]);
  });

  it("does not flag a plain SELECT on an ordinary column", () => {
    expect(analyzeGrants([g("authenticated", "posts", "title", "SELECT")])).toEqual([]);
  });

  it("does not flag a single ordinary write", () => {
    expect(analyzeGrants([g("authenticated", "posts", "title", "UPDATE")])).toEqual([]);
  });

  // Grants widen silently as columns are added.
  it("warns on broad writes even without an entitlement column", () => {
    const many = ["a", "b", "c", "d", "e", "f"].map((c) => g("authenticated", "posts", c, "UPDATE"));
    const out = analyzeGrants(many);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("inherited by every column added afterwards");
  });

  it("reports entitlement instead of the broad-write warning, not both", () => {
    const many = ["a", "b", "c", "d", "e", "is_paid"].map((c) => g("authenticated", "billing", c, "UPDATE"));
    const out = analyzeGrants(many);
    expect(out.filter((x) => x.id.includes("broad_write"))).toEqual([]);
    expect(out.filter((x) => x.id.includes("entitlement_writable"))).toHaveLength(1);
  });

  it("separates anon from authenticated", () => {
    const out = analyzeGrants([
      g("anon", "user_profiles", "is_paid", "UPDATE"),
      g("authenticated", "user_profiles", "is_paid", "UPDATE"),
    ]);
    expect(out).toHaveLength(2);
  });

  it("tolerates malformed rows", () => {
    expect(analyzeGrants([{ grantee: "", table: "", column: "", privilege: "" }])).toEqual([]);
  });

  it("handles an empty grant list", () => {
    expect(analyzeGrants([])).toEqual([]);
  });

  it("produces stable ids", () => {
    const rows = [g("anon", "t", "is_paid", "UPDATE")];
    expect(analyzeGrants(rows).map((x) => x.id)).toEqual(analyzeGrants(rows).map((x) => x.id));
  });
});

describe("the inventory query", () => {
  // It runs through the read-only transport, so it must satisfy that guard.
  it("passes assertReadOnly", () => {
    expect(() => assertReadOnly(GRANT_INVENTORY_SQL)).not.toThrow();
  });

  it("asks only about the roles a browser can reach", () => {
    expect(GRANT_INVENTORY_SQL).toContain("'anon'");
    expect(GRANT_INVENTORY_SQL).toContain("'authenticated'");
    expect(GRANT_INVENTORY_SQL).toContain("column_privileges");
  });
});

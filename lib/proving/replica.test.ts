import { describe, expect, it } from "vitest";
import {
  assessReplicability,
  buildControlProbeSql,
  buildReplicaPlan,
  buildReplicaProbeSql,
  ident,
  isTrustworthy,
} from "./replica";
import { TENANT_A, TENANT_B } from "./tenantProbe";
import type { PgPolicy } from "@/lib/deep/policyScan";

const pol = (over: Partial<PgPolicy> = {}): PgPolicy => ({
  schemaname: "public",
  tablename: "invoices",
  policyname: "p",
  cmd: "SELECT",
  qual: "true",
  with_check: null,
  roles: ["authenticated"],
  ...over,
});

describe("replicability — a wrong proof is worse than no proof", () => {
  it("accepts a policy that only uses the row and the caller", () => {
    expect(assessReplicability([pol({ qual: "(auth.uid() = user_id)" })]).replicable).toBe(true);
    expect(assessReplicability([pol({ qual: "true" })]).replicable).toBe(true);
    expect(assessReplicability([pol({ qual: "(user_id = auth.uid() and status = 'active')" })]).replicable).toBe(true);
  });

  // A policy evaluated without its dependency gives a different answer.
  it("REFUSES a policy that queries another table", () => {
    const v = assessReplicability([
      pol({ qual: "(exists (select 1 from memberships m where m.user_id = auth.uid()))" }),
    ]);
    expect(v.replicable).toBe(false);
    expect(v.reason).toContain("queries another table");
  });

  it("refuses a policy calling a custom function", () => {
    const v = assessReplicability([pol({ qual: "(is_org_admin(auth.uid()))" })]);
    expect(v.replicable).toBe(false);
    expect(v.reason).toContain("is_org_admin()");
  });

  it("refuses when the WITH CHECK clause reaches out, even if USING is simple", () => {
    expect(
      assessReplicability([pol({ qual: "(auth.uid() = user_id)", with_check: "(select count(*) from x) > 0" })])
        .replicable
    ).toBe(false);
  });

  it("refuses when there are no policies to reconstruct", () => {
    expect(assessReplicability([]).replicable).toBe(false);
  });

  it("allows the auth helpers and plain SQL functions we can guarantee", () => {
    expect(assessReplicability([pol({ qual: "(coalesce(auth.jwt() ->> 'org', '') = tenant)" })]).replicable).toBe(true);
    expect(assessReplicability([pol({ qual: "(lower(email) = lower(auth.jwt() ->> 'email'))" })]).replicable).toBe(true);
  });

  it("refuses if ANY policy in the set is not replicable", () => {
    expect(
      assessReplicability([pol({ qual: "(auth.uid() = user_id)" }), pol({ qual: "(exists (select 1 from t))" })])
        .replicable
    ).toBe(false);
  });
});

describe("replica construction", () => {
  const plan = buildReplicaPlan("run123", "invoices", "user_id", [pol({ qual: "true" })]);

  it("builds an isolated schema", () => {
    expect(plan.schema).toMatch(/^proving_[a-z0-9]+$/);
    expect(plan.setupSql).toContain(`create schema "${plan.schema}"`);
  });

  it("enables RLS and recreates the policy verbatim", () => {
    expect(plan.setupSql).toContain("enable row level security");
    expect(plan.setupSql).toContain("USING (true)");
    expect(plan.setupSql).toContain('for SELECT TO "authenticated"');
  });

  it("seeds exactly two synthetic tenants", () => {
    expect(plan.setupSql).toContain(TENANT_A);
    expect(plan.setupSql).toContain(TENANT_B);
  });

  it("grants the roles the policy is written for, or RLS blocks everything", () => {
    expect(plan.setupSql).toContain("grant select");
    expect(plan.setupSql).toContain("grant usage on schema");
  });

  // A partially-built replica must still disappear completely.
  it("tears down with CASCADE and IF EXISTS", () => {
    expect(plan.teardownSql).toContain("drop schema if exists");
    expect(plan.teardownSql).toContain("cascade");
  });

  it("refuses non-identifier table and column names", () => {
    expect(() => buildReplicaPlan("r", 'x"; drop schema public; --', "user_id", [pol()])).toThrow(/non-identifier/);
    expect(() => buildReplicaPlan("r", "invoices", "a b", [pol()])).toThrow();
  });

  it("ignores role names that are not plain identifiers", () => {
    const p = buildReplicaPlan("r", "invoices", "user_id", [pol({ roles: ['bad"role'] })]);
    expect(p.setupSql).not.toContain('bad"role');
  });

  it("quotes identifiers", () => {
    expect(ident("invoices")).toBe('"invoices"');
  });
});

describe("probes", () => {
  it("signs in as tenant A and counts tenant B's rows", () => {
    const sql = buildReplicaProbeSql("proving_x", "invoices", "user_id");
    expect(sql).toContain("set local role authenticated");
    expect(sql).toContain(TENANT_A); // in the claims
    expect(sql).toContain(TENANT_B); // in the WHERE
    expect(sql).toContain("leaked");
  });

  it("sets the JWT claims so auth.uid() resolves to the synthetic tenant", () => {
    expect(buildReplicaProbeSql("s", "t", "c")).toContain("request.jwt.claims");
  });

  it("runs in a transaction, because set local requires one", () => {
    const sql = buildReplicaProbeSql("s", "t", "c");
    expect(sql.startsWith("begin;")).toBe(true);
    expect(sql.trim().endsWith("commit;")).toBe(true);
  });

  // Without this, a broken replica reports "no leak" for every table and a
  // silent setup failure becomes a clean bill of health.
  it("has a control probe counting tenant A's OWN rows", () => {
    const sql = buildControlProbeSql("proving_x", "invoices", "user_id");
    expect(sql).toContain("visible");
    expect(sql).toContain(TENANT_A);
    expect(sql).not.toContain(TENANT_B);
  });
});

describe("trustworthiness", () => {
  const base = { table: "invoices", ownerColumn: "user_id", leakedRows: 0, controlRows: 1, executed: true };

  it("trusts a run where the control saw exactly its own row", () => {
    expect(isTrustworthy(base)).toBe(true);
  });

  // The failure this exists to catch: the replica silently denied everything, so
  // "no leak" would have been meaningless.
  it("does NOT trust a run where the control saw nothing", () => {
    expect(isTrustworthy({ ...base, controlRows: 0 })).toBe(false);
  });

  it("does not trust a run where the control saw too much", () => {
    expect(isTrustworthy({ ...base, controlRows: 2 })).toBe(false);
  });

  it("does not trust a run that did not execute", () => {
    expect(isTrustworthy({ ...base, executed: false })).toBe(false);
  });
});

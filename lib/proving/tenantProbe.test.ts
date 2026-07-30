import { describe, expect, it } from "vitest";
import {
  buildSeedSql,
  interpretProbe,
  pickOwnerColumn,
  quoteIdent,
  selectTablesToProbe,
  TENANT_A,
  TENANT_B,
} from "./tenantProbe";

describe("owner column detection", () => {
  it("finds the common ownership columns", () => {
    for (const c of ["user_id", "owner_id", "tenant_id", "org_id", "created_by"]) {
      expect(pickOwnerColumn(["id", c, "created_at"]), c).toBe(c);
    }
  });

  it("is case-insensitive", () => {
    expect(pickOwnerColumn(["User_ID"])).toBe("user_id");
  });

  // Guessing the column would produce a confident, meaningless answer.
  it("returns null when no column looks like an owner", () => {
    expect(pickOwnerColumn(["id", "title", "created_at"])).toBeNull();
  });

  it("prefers user_id when several candidates exist", () => {
    expect(pickOwnerColumn(["org_id", "user_id"])).toBe("user_id");
  });
});

describe("SQL construction", () => {
  it("quotes identifiers", () => {
    expect(quoteIdent("invoices")).toBe('"invoices"');
  });

  // Refused rather than escaped: malformed SQL would make results
  // uninterpretable even on a throwaway branch.
  it("REFUSES a non-identifier rather than escaping it", () => {
    expect(() => quoteIdent('invoices"; drop table x; --')).toThrow(/non-identifier/);
    expect(() => quoteIdent("has space")).toThrow();
  });

  it("seeds exactly two synthetic tenants", () => {
    const plan = buildSeedSql("invoices", "user_id");
    expect(plan.sql).toContain(TENANT_A);
    expect(plan.sql).toContain(TENANT_B);
    expect(plan.sql).toContain('insert into public."invoices" ("user_id")');
  });


});

describe("interpreting the result", () => {
  const outcome = { table: "invoices", ownerColumn: "user_id", leakedRows: 1, executed: true };

  it("reports a finding when another tenant's rows were visible", () => {
    const f = interpretProbe(outcome)!;
    expect(f.severity).toBe("CRITICAL");
    expect(f.proven).toBe(true);
  });

  // The distinction that justifies the whole feature.
  it("says plainly that this is what happened, not what might", () => {
    const f = interpretProbe(outcome)!;
    expect(f.consequence).toContain("not a warning based on reading your policies");
    expect(f.consequence).toContain("what actually happened when we tried");
  });

  it("states that no real data was involved", () => {
    expect(interpretProbe(outcome)!.consequence).toContain("with none of your data");
  });

  it("promises to re-run and close on evidence", () => {
    expect(interpretProbe(outcome)!.consequence).toContain("re-run this same probe");
  });

  it("reports NOTHING when isolation held", () => {
    expect(interpretProbe({ ...outcome, leakedRows: 0 })).toBeNull();
  });

  // The static graph already covers the inference case; a second weaker voice
  // saying the same thing would double-count it.
  it("reports nothing when the probe did not run — never 'possibly vulnerable'", () => {
    expect(interpretProbe({ ...outcome, executed: false, skippedReason: "no owner column" })).toBeNull();
  });

  it("singularises one leaked row", () => {
    expect(interpretProbe(outcome)!.consequence).toContain("1 row belonging");
  });
});

describe("selecting what to probe", () => {
  const schema = new Map([
    ["invoices", ["id", "user_id", "amount"]],
    ["orders", ["id", "owner_id"]],
    ["settings", ["id", "key", "value"]],
  ]);

  // The graph decides WHAT to test; the proving ground decides whether it is
  // TRUE. That is what makes them complement rather than duplicate.
  it("probes only what the reasoner already suspects", () => {
    expect(selectTablesToProbe(["public.invoices"], schema)).toEqual([
      { table: "invoices", ownerColumn: "user_id" },
    ]);
  });

  it("skips a table with no ownership column", () => {
    expect(selectTablesToProbe(["public.settings"], schema)).toEqual([]);
  });

  it("skips a table absent from the schema", () => {
    expect(selectTablesToProbe(["public.ghost"], schema)).toEqual([]);
  });

  it("refuses a table name that is not a plain identifier", () => {
    const nasty = new Map([['x"; drop table y; --', ["user_id"]]]);
    expect(selectTablesToProbe(['x"; drop table y; --'], nasty)).toEqual([]);
  });

  // Each run costs real money and takes minutes.
  it("caps how many tables one run probes", () => {
    const big = new Map(Array.from({ length: 20 }, (_, i) => [`t${i}`, ["id", "user_id"]]));
    expect(selectTablesToProbe(Array.from({ length: 20 }, (_, i) => `t${i}`), big)).toHaveLength(5);
  });

  it("handles empty input", () => {
    expect(selectTablesToProbe([], schema)).toEqual([]);
  });
});

import { describe, expect, it } from "vitest";
import { buildFixApplySql, buildGateSql, buildOwnershipFix, judgeFix } from "./fixValidation";
import { TENANT_A, TENANT_B } from "./tenantProbe";

const fix = buildOwnershipFix("user_id");

describe("the three gates", () => {
  it("validates a fix that closes the hole and keeps legitimate access", () => {
    const v = judgeFix({ leaked: 1, own: 1 }, { leaked: 0, own: 1 }, fix);
    expect(v).toMatchObject({ reproduced: "pass", closed: "pass", preserved: "pass", validated: true });
  });

  // THE GATE THAT EXISTS TO STOP US. `USING (false)` closes every attack and
  // takes every user offline with it.
  it("REJECTS a fix that stops the attack by locking everyone out", () => {
    const v = judgeFix({ leaked: 1, own: 1 }, { leaked: 0, own: 0 }, fix);
    expect(v.closed).toBe("pass");
    expect(v.preserved).toBe("fail");
    expect(v.validated).toBe(false);
    expect(v.summary).toContain("lock your users out of their own data");
  });

  it("rejects a fix that does not close the hole", () => {
    const v = judgeFix({ leaked: 1, own: 1 }, { leaked: 1, own: 1 }, fix);
    expect(v.closed).toBe("fail");
    expect(v.validated).toBe(false);
    expect(v.summary).toContain("did not work");
  });

  // Withdraw the finding rather than change a database on a guess.
  it("WITHDRAWS when the attack cannot be reproduced against the original", () => {
    const v = judgeFix({ leaked: 0, own: 1 }, { leaked: 0, own: 1 }, fix);
    expect(v.reproduced).toBe("fail");
    expect(v.validated).toBe(false);
    expect(v.summary).toContain("finding is probably wrong");
    expect(v.summary).toContain("rather withdraw a finding");
  });

  it("does not validate when the before reading is missing", () => {
    expect(judgeFix(null, { leaked: 0, own: 1 }, fix).validated).toBe(false);
  });

  it("does not validate when the after reading is missing", () => {
    const v = judgeFix({ leaked: 1, own: 1 }, null, fix);
    expect(v.reproduced).toBe("pass");
    expect(v.closed).toBe("not_run");
    expect(v.validated).toBe(false);
  });

  it("never marks validated unless all three gates passed", () => {
    const combos: [number, number, number][] = [
      [1, 0, 1], [1, 1, 1], [1, 0, 0], [0, 0, 1], [1, 1, 0],
    ];
    for (const [bLeak, aLeak, aOwn] of combos) {
      const v = judgeFix({ leaked: bLeak, own: 1 }, { leaked: aLeak, own: aOwn }, fix);
      const allPass = v.reproduced === "pass" && v.closed === "pass" && v.preserved === "pass";
      expect(v.validated).toBe(allPass);
    }
  });

  it("explains that preserving access is the part checked hardest", () => {
    expect(judgeFix({ leaked: 1, own: 1 }, { leaked: 0, own: 1 }, fix).summary).toContain(
      "a policy that blocks everyone would also stop the attack"
    );
  });

  it("states that no real data was used", () => {
    expect(judgeFix({ leaked: 1, own: 1 }, { leaked: 0, own: 1 }, fix).summary).toContain("no real data");
  });
});

describe("the candidate fix", () => {
  it("is the most conservative correct policy, readable at a glance", () => {
    expect(fix.policies[0].qual).toBe("auth.uid() = user_id");
    expect(fix.policies[0].cmd).toBe("SELECT");
  });

  it("refuses a non-identifier owner column", () => {
    expect(() => buildOwnershipFix('x"; drop table y; --')).toThrow(/non-identifier/);
  });

  it("targets the roles it is given", () => {
    expect(buildOwnershipFix("user_id", ["authenticated", "anon"]).policies[0].roles).toEqual([
      "authenticated",
      "anon",
    ]);
  });
});

describe("SQL construction", () => {
  it("drops every original policy before creating the fix", () => {
    const sql = buildFixApplySql("proving_x", "invoices", 2, fix);
    expect(sql).toContain('drop policy if exists "p_0"');
    expect(sql).toContain('drop policy if exists "p_1"');
    expect(sql).toContain('create policy "fix_0"');
    expect(sql.indexOf("drop policy")).toBeLessThan(sql.indexOf("create policy"));
  });

  it("measures both gates in one transaction and one auth context", () => {
    const sql = buildGateSql("proving_x", "invoices", "user_id");
    expect(sql).toContain("set local role authenticated");
    expect(sql).toContain("leaked");
    expect(sql).toContain("own");
    expect(sql).toContain(TENANT_A);
    expect(sql).toContain(TENANT_B);
    expect(sql.match(/begin;/g)).toHaveLength(1);
  });

  it("refuses non-identifier schema and table names", () => {
    expect(() => buildFixApplySql('x"; drop schema public; --', "t", 1, fix)).toThrow();
    expect(() => buildGateSql("s", "a b", "c")).toThrow();
  });
});

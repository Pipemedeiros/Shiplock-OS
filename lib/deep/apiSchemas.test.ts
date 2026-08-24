import { describe, expect, it } from "vitest";
import {
  CollectorShapeError,
  ColumnGrantRow,
  parseObject,
  parseRows,
  PgPolicyRow,
  PgRoleArray,
  RoleFlagsRow,
  SupabaseAdvisorRow,
  SupabaseAuthConfigObject,
  WriteGrantCountRow,
} from "./apiSchemas";
import { findAttackPaths } from "@/lib/graph/attackPaths";
import type { RouteFact } from "@/lib/graph/routeInventory";

// These tests exist for one failure, and it is worth naming precisely because
// it is invisible by construction: an API changes shape, the cast that used to
// stand in for validation produces objects whose fields are all `undefined`,
// every predicate downstream reads false, and the customer is shown a clean
// scan of a leaking database. No error, no alert, nothing to notice.
//
// So the assertions below are less about Zod and more about a rule: a fact we
// did not successfully read must never become a fact we assert.

const policyRow = {
  schemaname: "public",
  tablename: "invoices",
  policyname: "read_all",
  cmd: "SELECT",
  qual: "true",
  with_check: null,
  roles: ["authenticated"],
};

describe("parseRows", () => {
  it("accepts a well-formed payload", () => {
    const rows = parseRows("test", PgPolicyRow, [policyRow]);
    expect(rows).toHaveLength(1);
    expect(rows[0].qual).toBe("true");
  });

  it("throws rather than returning [] when the payload is not a list", () => {
    // The old code did `Array.isArray(json) ? json as T[] : []`, so a
    // `{ data: [...] }` envelope became zero policies — indistinguishable from a
    // database with no policies at all.
    expect(() => parseRows("test", PgPolicyRow, { data: [policyRow] })).toThrow(
      CollectorShapeError
    );
  });

  it("throws when a field the reasoner reads has been renamed", () => {
    // THE bug: `qual` -> `using_expr`. Under a cast this parsed fine and
    // isPermissiveExpression(undefined) returned false, silently clearing a
    // USING (true) finding.
    const renamed = { ...policyRow, using_expr: "true" } as Record<string, unknown>;
    delete renamed.qual;
    expect(() => parseRows("test", PgPolicyRow, [renamed])).toThrow(CollectorShapeError);
  });

  it("tolerates fields being ADDED, because that is not a breakage", () => {
    // Failing on new keys would make us fragile in the direction that costs the
    // customer their scan for no reason.
    expect(parseRows("test", PgPolicyRow, [{ ...policyRow, new_column: 1 }])).toHaveLength(1);
  });

  it("accepts null qual/with_check, which are legitimate", () => {
    // An INSERT-only policy has no USING expression. Requiring it would fail
    // valid databases; making it optional is what let a renamed field pass.
    expect(
      parseRows("test", PgPolicyRow, [{ ...policyRow, qual: null, with_check: "true" }])
    ).toHaveLength(1);
  });

  it("fails the whole batch when any row is malformed", () => {
    // All-or-nothing: a single bad row means the contract moved, and the rows
    // that still parse are the ones whose fields happen to overlap the old
    // shape. Keeping those would hand the reasoner a silently partial database.
    const bad = { ...policyRow, qual: 42 };
    expect(() => parseRows("test", PgPolicyRow, [policyRow, bad])).toThrow(CollectorShapeError);
  });

  it("reports how many rows failed", () => {
    try {
      parseRows("test", PgPolicyRow, [{ ...policyRow, qual: 1 }, { ...policyRow, qual: 2 }]);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as CollectorShapeError).failedRows).toBe(2);
    }
  });
});

describe("errors never carry customer data", () => {
  // The payloads validated here ARE the customer's schema — table names, column
  // names, row counts. Zod's default messages interpolate the received value,
  // so an unfiltered error would put a customer's table names into our logs.
  // "ShipLock never reads your users' data" is customer-facing copy.
  it("omits values from the message, keeping only path and expected type", () => {
    try {
      parseRows("test", PgPolicyRow, [{ ...policyRow, tablename: 12345, qual: "SECRET_VALUE" }]);
      throw new Error("should have thrown");
    } catch (err) {
      const message = (err as Error).message;
      expect(message).not.toContain("SECRET_VALUE");
      expect(message).not.toContain("12345");
      expect(message).toContain("tablename");
      expect(message).toContain("expected");
    }
  });

  it("names the source so a failure says which layer broke", () => {
    try {
      parseRows("fetchPolicies", PgPolicyRow, "nonsense");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Error).message).toContain("fetchPolicies");
    }
  });
});

describe("PgRoleArray", () => {
  it("accepts a real array", () => {
    expect(PgRoleArray.parse(["anon", "authenticated"])).toEqual(["anon", "authenticated"]);
  });

  it("parses the stringified form some transports return", () => {
    expect(PgRoleArray.parse("{anon,authenticated}")).toEqual(["anon", "authenticated"]);
  });

  it("treats null as no roles", () => {
    expect(PgRoleArray.parse(null)).toEqual([]);
  });
});

describe("the two schemas that gate holding a credential", () => {
  // Both of these were read with optional chaining over an unvalidated row, so a
  // renamed column would have produced `undefined` (falsy) and `0` respectively
  // — approving a superuser or a writable role. The checks that exist to stop us
  // holding too much power would have been the ones that failed open.
  it("rejects a role row missing the superuser flag", () => {
    expect(() => parseRows("roleFlags", RoleFlagsRow, [{ rolbypassrls: false }])).toThrow(
      CollectorShapeError
    );
  });

  it("rejects a write-grant row missing the count", () => {
    expect(() => parseRows("writeGrants", WriteGrantCountRow, [{}])).toThrow(CollectorShapeError);
  });

  it("accepts a bigint count returned as a string", () => {
    expect(parseRows("writeGrants", WriteGrantCountRow, [{ count: "3" }])[0].count).toBe(3);
  });
});

describe("deliberately permissive schemas", () => {
  it("accepts advisors with only some fields, because the payload varies by version", () => {
    expect(parseRows("advisors", SupabaseAdvisorRow, [{ name: "0024_x" }, {}])).toHaveLength(2);
  });

  it("still rejects an advisor payload that is not objects at all", () => {
    expect(() => parseRows("advisors", SupabaseAdvisorRow, ["a string"])).toThrow(
      CollectorShapeError
    );
  });

  it("accepts any auth config object but rejects an array", () => {
    // `typeof [] === "object"` passed the old check and handed the auth scanners
    // something with no keys — which reads as "every setting absent", i.e. clean.
    expect(parseObject("authConfig", SupabaseAuthConfigObject, { disable_signup: false })).toEqual({
      disable_signup: false,
    });
    expect(() => parseObject("authConfig", SupabaseAuthConfigObject, [])).toThrow(
      CollectorShapeError
    );
  });

  it("validates grant rows, which name real columns", () => {
    expect(
      parseRows("grants", ColumnGrantRow, [
        { grantee: "anon", table_name: "users", column_name: "email", privilege_type: "SELECT" },
      ])
    ).toHaveLength(1);
  });
});

describe("the end-to-end consequence", () => {
  const route: RouteFact = {
    path: "/api/invoices",
    file: "app/api/invoices/route.ts",
    methods: ["GET"],
    tables: ["invoices"],
    authenticated: true,
    machineGated: false,
    ownershipFiltered: false,
    usesServiceRole: false,
    isApiRoute: true,
    via: [],
  };

  it("reports the leak when the policy is readable", () => {
    const paths = findAttackPaths({ routes: [route], policies: [policyRow] });
    expect(paths).toHaveLength(1);
    expect(paths[0].severity).toBe("CRITICAL");
  });

  it("does not silently clear the leak when policies were never read", () => {
    // Before this work, `policies: undefined` plus `rlsEnabled: true` made
    // storeProtects return TRUE — "protected" concluded from an enforcement flag
    // with no policy ever read, which is exactly where a USING (true) policy
    // lives. Now it returns null, and the anonymous-route path reports a WARNING
    // that names what it could not check.
    const anon = { ...route, authenticated: false };
    const paths = findAttackPaths({
      routes: [anon],
      scanTables: [{ name: "invoices", rlsEnabled: true }],
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].severity).toBe("WARNING");
    expect(paths[0].id).toContain("anon_sensitive_unknown");
  });

  it("stays silent for an authenticated unscoped route with rules unread — a known gap", () => {
    // Documented rather than asserted-away. `storeProtects` now correctly returns
    // null here instead of true, but no attack path currently reports the
    // authenticated equivalent of `anon_sensitive_unknown`, so this case is
    // silent either way.
    //
    // Left alone deliberately: the authenticated version would fire on every
    // signed-in route over a sensitive table whose ownership filter we could not
    // detect, and ownership detection has known false negatives (OWNERSHIP_RE in
    // routeInventory.ts). That is a noise trade, not a correctness one, and it
    // deserves its own decision rather than riding along with this change.
    const authed = { ...route, authenticated: true };
    expect(
      findAttackPaths({ routes: [authed], scanTables: [{ name: "invoices", rlsEnabled: true }] })
    ).toEqual([]);
  });
});

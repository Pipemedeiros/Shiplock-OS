import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findAttackPaths } from "./attackPaths";
import { buildAuthzFacts, observedProvider } from "./graph";
import { isProvable, vocabulary, type AuthzProvider } from "./providers";
import type { RouteFact } from "./routeInventory";

const ALL: AuthzProvider[] = ["postgres-rls", "firebase-rules", "app-layer"];

describe("provider vocabulary", () => {
  it("has complete wording for every provider", () => {
    for (const id of ALL) {
      const v = vocabulary(id);
      expect(v.id).toBe(id);
      for (const field of [
        "label",
        "mechanism",
        "notEnforced",
        "unconditional",
        "callerScopeRemedy",
        "bypassNote",
        "configLabel",
      ] as const) {
        expect(v[field], `${id}.${field}`).toBeTruthy();
      }
      expect(v.ownershipRemedy("public.invoices")).toContain("public.invoices");
    }
  });

  it("falls back to app-layer wording when no provider was observed", () => {
    // Not an error state: a customer with only GitHub connected has route facts
    // and no store facts. Application code really is the only control we know of.
    expect(vocabulary(null).id).toBe("app-layer");
    expect(vocabulary(undefined).id).toBe("app-layer");
  });

  it("treats only postgres-rls as provable today", () => {
    // If this ever flips for another provider, a prover must exist for it first.
    // `provable` gates whether a leak may be reproduced rather than inferred, and
    // a provider claiming it without a working prover would surface inference as
    // proof — the one thing the proving ground exists to prevent.
    expect(isProvable("postgres-rls")).toBe(true);
    expect(isProvable("firebase-rules")).toBe(false);
    expect(isProvable("app-layer")).toBe(false);
    expect(isProvable(null)).toBe(false);
  });
});

describe("the reasoner stays provider-neutral", () => {
  // This is an ARCHITECTURAL guard, not a style check. The reasoner's value is
  // that it reasons about authorization rather than about Postgres; the moment
  // it names a technology or branches on a provider id, adding the next store
  // means reopening every attack path. Failing here means the seam has closed —
  // move the wording into `providers.ts` rather than deleting the assertion.
  const source = readFileSync(join(__dirname, "attackPaths.ts"), "utf8");
  const code = source
    .split("\n")
    .filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*"))
    .join("\n");

  it("names no specific technology in the code it emits", () => {
    for (const banned of [
      "Row Level Security",
      "RLS",
      "Supabase",
      "auth.uid",
      "Firestore",
      "service-role key",
    ]) {
      expect(code, `attackPaths.ts must not mention "${banned}"`).not.toContain(banned);
    }
  });

  it("never branches on a provider id", () => {
    for (const id of ALL) {
      expect(code, `attackPaths.ts must not compare against "${id}"`).not.toContain(`"${id}"`);
    }
  });
});

describe("the same facts read correctly on a different provider", () => {
  // The real test of the refactor: identical structural facts, different store,
  // and the finding still fires with wording that suits the customer's stack.
  const route: RouteFact = {
    path: "/api/invoices",
    file: "app/api/invoices/route.ts",
    methods: ["GET"],
    tables: ["invoices"],
    authenticated: false,
    machineGated: false,
    ownershipFiltered: false,
    usesServiceRole: false,
    isApiRoute: true,
    identityReadable: true,
    identityGap: null,
    via: [],
  };

  const forProvider = (authzProvider: AuthzProvider) =>
    findAttackPaths({
      authzProvider,
      routes: [route],
      scanTables: [{ name: "invoices", rlsEnabled: false }],
    });

  it("fires the anonymous-read path on Postgres, in Postgres words", () => {
    const [path] = forProvider("postgres-rls");
    expect(path.severity).toBe("CRITICAL");
    expect(path.surfaces).toEqual(["source", "db"]);
    expect(path.consequence).toContain("Row Level Security");
  });

  it("fires the same path on Firestore, in Firestore words", () => {
    const [path] = forProvider("firebase-rules");
    expect(path.severity).toBe("CRITICAL");
    expect(path.surfaces).toEqual(["source", "db"]);
    expect(path.consequence).toContain("security rule");
    expect(path.consequence).not.toContain("Row Level Security");
  });

  it("produces the same path id regardless of provider", () => {
    // Finding ids feed the diff engine and the 7-day dedup log. If they moved
    // with the provider, a customer would be re-alerted about an unchanged
    // problem the first time a collector reported its store differently.
    expect(forProvider("postgres-rls")[0].id).toBe(forProvider("firebase-rules")[0].id);
  });
});

describe("provider inference", () => {
  it("infers Postgres only once a database collector has reported", () => {
    expect(observedProvider({})).toBeNull();
    expect(observedProvider({ routes: [] })).toBeNull();
    expect(observedProvider({ scanTables: [{ name: "orders", rlsEnabled: true }] })).toBe("postgres-rls");
    expect(observedProvider({ advisors: [{ name: "0013_rls_disabled_in_public" }] })).toBe("postgres-rls");
  });

  it("does not report unknown authorization as unprotected", () => {
    // The doctrine's floor: with no store facts, an anonymous route over a
    // sensitive table is a WARNING that says what we could not check — never a
    // CRITICAL that asserts a database fact we never observed.
    const paths = findAttackPaths({
      routes: [
        {
          path: "/api/users",
          file: "app/api/users/route.ts",
          methods: ["GET"],
          tables: ["users"],
          authenticated: false,
          machineGated: false,
          ownershipFiltered: false,
          usesServiceRole: false,
          isApiRoute: true,
          identityReadable: true,
          identityGap: null,
          via: [],
        },
      ],
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].severity).toBe("WARNING");
    expect(buildAuthzFacts({}).size).toBe(0);
  });
});

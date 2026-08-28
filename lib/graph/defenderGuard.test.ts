import { describe, it, expect } from "vitest";
import {
  applyDefence,
  downrank,
  isDefensible,
  parseClaims,
  verifyClaim,
  type DefenceEvidence,
  type VerifiedClaim,
} from "./defenderGuard";
import type { AttackPath } from "./attackPaths";
import type { AuthzFacts } from "./graph";
import type { RouteFact } from "./routeInventory";

function route(over: Partial<RouteFact> = {}): RouteFact {
  return {
    path: "/api/invoices",
    file: "app/api/invoices/route.ts",
    methods: ["GET"],
    tables: ["invoices"],
    authenticated: false,
    machineGated: false,
    usesServiceRole: false,
    ownershipFiltered: false,
    isApiRoute: true,
    via: [],
    ...over,
  };
}

function table(over: Partial<AuthzFacts> = {}): AuthzFacts {
  return {
    schema: "public",
    name: "invoices",
    qualified: "public.invoices",
    provider: "postgres-rls",
    enforced: true,
    unconditionalGrant: false,
    rulesRead: true,
    grantedRoles: [],
    provable: true,
    sensitive: true,
    ...over,
  };
}

function evidence(over: Partial<DefenceEvidence> = {}): DefenceEvidence {
  return { routes: [route()], tables: [table()], ...over };
}

function path(over: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "graph:anon_sensitive_unknown:public.invoices",
    severity: "CRITICAL",
    title: "Anonymous route reaches invoices",
    consequence: "…",
    evidence: [{ collector: "source", fact: "route is anonymous" }],
    score: 90,
    surfaces: ["source", "db"],
    ...over,
  };
}

function verified(over: Partial<VerifiedClaim>): VerifiedClaim {
  return { kind: "route_authenticated", verdict: "confirmed", basis: "b", ...over } as VerifiedClaim;
}

describe("verifyClaim", () => {
  it("confirms an ownership filter that the collector observed", () => {
    const v = verifyClaim(
      { kind: "route_ownership_filtered", route: "/api/invoices" },
      evidence({ routes: [route({ ownershipFiltered: true })] })
    );
    expect(v.verdict).toBe("confirmed");
  });

  it("refutes an ownership filter the collector did not observe", () => {
    const v = verifyClaim({ kind: "route_ownership_filtered", route: "/api/invoices" }, evidence());
    expect(v.verdict).toBe("refuted");
  });

  it("cannot verify a claim about a route we have no facts for", () => {
    const v = verifyClaim({ kind: "route_ownership_filtered", route: "/api/ghost" }, evidence());
    expect(v.verdict).toBe("unverifiable");
  });

  // The distinction rulesRead exists to preserve. A table with enforcement ON
  // and policies unread is precisely where a permissive rule hides, so a
  // defence there must never be confirmable.
  it("will not confirm store enforcement when the rules were never read", () => {
    const v = verifyClaim(
      { kind: "store_rule_enforced", table: "public.invoices" },
      evidence({ tables: [table({ enforced: true, rulesRead: false })] })
    );
    expect(v.verdict).toBe("unverifiable");
    expect(v.basis).toMatch(/never read/i);
  });

  it("refutes store enforcement when a rule grants access unconditionally", () => {
    const v = verifyClaim(
      { kind: "store_rule_enforced", table: "public.invoices" },
      evidence({ tables: [table({ unconditionalGrant: true })] })
    );
    expect(v.verdict).toBe("refuted");
  });

  it("confirms store enforcement only when enforced, read, and not unconditional", () => {
    const v = verifyClaim({ kind: "store_rule_enforced", table: "public.invoices" }, evidence());
    expect(v.verdict).toBe("confirmed");
  });

  // An `authenticated` flag with no witnessing module is a collector inference.
  // Inference does not get to defend against inference.
  it("will not confirm authentication with no gating module identified", () => {
    const v = verifyClaim(
      { kind: "route_authenticated", route: "/api/invoices" },
      evidence({ routes: [route({ authenticated: true, via: [] })] })
    );
    expect(v.verdict).toBe("unverifiable");
  });

  it("confirms authentication when a gating module was identified", () => {
    const v = verifyClaim(
      { kind: "route_authenticated", route: "/api/invoices" },
      evidence({ routes: [route({ authenticated: true, via: ["lib/auth.ts"] })] })
    );
    expect(v.verdict).toBe("confirmed");
  });

  it("confirms that a route does not reference a table it never names", () => {
    const v = verifyClaim(
      { kind: "table_not_referenced", route: "/api/invoices", table: "public.payments" },
      evidence()
    );
    expect(v.verdict).toBe("confirmed");
  });

  it("refutes table_not_referenced when the route does name it", () => {
    const v = verifyClaim(
      { kind: "table_not_referenced", route: "/api/invoices", table: "public.invoices" },
      evidence()
    );
    expect(v.verdict).toBe("refuted");
  });

  it("matches tables by bare name as well as qualified name", () => {
    expect(
      verifyClaim({ kind: "table_not_sensitive", table: "invoices" }, evidence()).verdict
    ).toBe("refuted");
  });
});

describe("applyDefence", () => {
  it("leaves a finding untouched when every claim is refuted", () => {
    const r = applyDefence(path(), [verified({ verdict: "refuted" })]);
    expect(r.outcome).toBe("unchanged");
    expect(r.severity).toBe("CRITICAL");
  });

  // The single most important assertion in this file.
  it("NEVER downranks on unverifiable claims — absence of proof is not proof", () => {
    const r = applyDefence(path(), [
      verified({ verdict: "unverifiable" }),
      verified({ verdict: "unverifiable", kind: "store_rule_enforced" }),
      verified({ verdict: "unverifiable", kind: "route_machine_gated" }),
    ]);
    expect(r.outcome).toBe("annotated");
    expect(r.severity).toBe("CRITICAL");
    expect(r.notes.every((n) => n.startsWith("Could not check"))).toBe(true);
  });

  it("downranks exactly one step on confirmed counter-evidence", () => {
    const r = applyDefence(path(), [verified({})]);
    expect(r.outcome).toBe("downranked");
    expect(r.severity).toBe("WARNING");
  });

  // Three weak mitigations are not a proof. Stacking would let a chatty model
  // argue a CRITICAL down to nothing.
  it("does not stack multiple confirmed claims into a bigger drop", () => {
    const r = applyDefence(path(), [
      verified({}),
      verified({ kind: "route_machine_gated" }),
      verified({ kind: "table_not_sensitive" }),
    ]);
    expect(r.severity).toBe("WARNING");
  });

  it("withdraws only on a disqualifying claim", () => {
    const r = applyDefence(path(), [verified({ kind: "table_not_referenced" })]);
    expect(r.outcome).toBe("withdrawn");
  });

  it("does not withdraw on a merely mitigating claim", () => {
    const r = applyDefence(path(), [verified({ kind: "store_rule_enforced" })]);
    expect(r.outcome).toBe("downranked");
  });

  it("records claims on the result even when they changed nothing", () => {
    const claims = [verified({ verdict: "refuted" })];
    expect(applyDefence(path(), claims).claims).toEqual(claims);
  });
});

describe("downrank", () => {
  it("steps down one level and floors at INFO", () => {
    expect(downrank("CRITICAL")).toBe("WARNING");
    expect(downrank("WARNING")).toBe("INFO");
    expect(downrank("INFO")).toBe("INFO");
  });
});

describe("isDefensible", () => {
  // Proof beats argument. A defender allowed near a proven finding is pure
  // downside: it can only turn a true finding into a quieter one.
  it("refuses to defend a proven finding", () => {
    expect(isDefensible(path({ id: "proven:agent_tenant_leak:app:invoices" }))).toBe(false);
  });

  it("allows inferred findings to be defended", () => {
    expect(isDefensible(path())).toBe(true);
  });
});

describe("parseClaims", () => {
  it("keeps well-formed claims of known kinds", () => {
    expect(parseClaims([{ kind: "route_authenticated", route: "/api/x" }])).toEqual([
      { kind: "route_authenticated", route: "/api/x" },
    ]);
  });

  it("discards unknown claim kinds", () => {
    expect(parseClaims([{ kind: "trust_me_bro", route: "/api/x" }])).toEqual([]);
  });

  it("discards claims with no subject to verify against", () => {
    expect(parseClaims([{ kind: "route_authenticated" }])).toEqual([]);
  });

  it("discards non-objects and non-arrays", () => {
    expect(parseClaims("nope")).toEqual([]);
    expect(parseClaims([null, 3, "x"])).toEqual([]);
  });

  it("bounds how many claims one finding may carry", () => {
    const many = Array.from({ length: 40 }, () => ({ kind: "route_authenticated", route: "/api/x" }));
    expect(parseClaims(many)).toHaveLength(12);
  });
});

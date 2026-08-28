import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { buildFindings, confidenceFrom, type Claim } from "./findings";
import type { StackReport } from "./stack";

const route: RouteFact = {
  path: "/api/invoices/[id]",
  file: "app/api/invoices/[id]/route.ts",
  methods: ["GET"],
  tables: ["invoices"],
  authenticated: true,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  isApiRoute: true,
  via: [],
};

const stack: StackReport = {
  tools: [{ id: "clerk", name: "Clerk", kind: "auth", evidence: '"@clerk/nextjs" in package.json', usedIn: [] }],
  authUnknown: false,
  databaseUnknown: false,
};

const hypothesis = {
  entry: "/api/invoices/[id]",
  attackClass: "missing_authorization" as const,
  title: "Any signed-in user can read another workspace's invoices",
  consequence: "A valid account is enough to retrieve other customers' billing records.",
  citedFiles: ["app/api/invoices/[id]/route.ts"],
};

describe("confidenceFrom", () => {
  it("never returns proven, whatever the evidence says", () => {
    // proven is a capability of lib/proving/*, which RUNS the attack on a
    // replica. A static reader awarding it to itself would make the one label
    // that means something mean nothing.
    const claims: Claim[] = [
      { claim: "a", origin: "routes", verified: true },
      { claim: "b", origin: "schema", verified: true },
      { claim: "c", origin: "stack", verified: true },
    ];
    expect(confidenceFrom(claims)).toBe("corroborated");
  });

  it("is inferred on a single origin, however many claims share it", () => {
    const claims: Claim[] = [
      { claim: "a", origin: "routes", verified: true },
      { claim: "b", origin: "routes", verified: true },
    ];
    expect(confidenceFrom(claims)).toBe("inferred");
  });

  it("ignores unverified claims when counting origins", () => {
    const claims: Claim[] = [
      { claim: "a", origin: "routes", verified: true },
      { claim: "the model thinks this is exploitable", origin: "agent", verified: false },
    ];
    expect(confidenceFrom(claims)).toBe("inferred");
  });
});

describe("buildFindings", () => {
  const base = { deterministic: [], routes: [route], stack, repositoryId: "r1", hasDatabase: false };

  it("attaches the route's own facts as verified claims", () => {
    const [finding] = buildFindings({ ...base, admitted: [hypothesis] });

    expect(finding.claims.filter((c) => c.verified).map((c) => c.origin)).toContain("routes");
    expect(finding.claims.some((c) => c.claim.includes("invoices"))).toBe(true);
    expect(finding.confidence).toBe("corroborated");
  });

  it("marks the model's own contribution unverified", () => {
    // The model's sentence is a proposal. It is shown, and it does not count
    // toward confidence.
    const [finding] = buildFindings({ ...base, admitted: [hypothesis] });
    expect(finding.claims.find((c) => c.origin === "agent")?.verified).toBe(false);
  });

  it("gives a mechanical gap a pull request and an architecture question a manual fix", () => {
    const findings = buildFindings({
      ...base,
      admitted: [hypothesis, { ...hypothesis, attackClass: "server_boundary_crossed" as const }],
    });
    expect(findings.find((f) => f.attackClass === "missing_authorization")?.fixKind).toBe("pr");
    expect(findings.find((f) => f.attackClass === "server_boundary_crossed")?.fixKind).toBe("manual");
  });

  it("gives a finding a stable id so the diff engine does not re-alert it", () => {
    const [a] = buildFindings({ ...base, admitted: [hypothesis] });
    const [b] = buildFindings({ ...base, admitted: [{ ...hypothesis, title: "reworded by the model" }] });
    expect(a.id).toBe(b.id);
  });

  it("makes a committed secret the customer's to rotate, not ours to patch", () => {
    // A pull request removing the line does not un-leak the key, and we do not
    // hold the credential to rotate it.
    const findings = buildFindings({
      ...base,
      admitted: [],
      deterministic: [{
        id: "secret:aws:config.ts",
        severity: "CRITICAL",
        title: "AWS key committed",
        consequence: "Anyone with repository access has it.",
        packageName: null, version: null, vulnId: null, cveId: null,
      }],
    });
    expect(findings[0].fixKind).toBe("manual");
  });

  it("orders critical findings first", () => {
    const findings = buildFindings({
      ...base,
      admitted: [{ ...hypothesis, attackClass: "unsafe_redirect" as const }, hypothesis],
    });
    expect(findings[0].severity).toBe("CRITICAL");
  });
});

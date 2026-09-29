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
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  ownershipReadable: true,
  ownershipGap: null,
  serviceRoleReadable: true,
  machineGateReadable: true,
  machineGateGap: null,
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
      admitted: [{ ...hypothesis, attackClass: "unsafe_redirect" as const }, { ...hypothesis, citedFacts: ["live:1"] }],
      liveFacts: [{ id: "live:1", statement: "Row level security is off on invoices." }],
    });
    expect(findings[0].severity).toBe("CRITICAL");
  });
});

// Q16: on a route we READ as anonymous there is no caller to narrow by, so a
// model's "across workspaces" story for missing_authorization is a mechanism we
// never read. The title and consequence come from what we read; the model's
// sentence stays, marked unverified. Id and severity are unchanged.
describe("missing_authorization on a route read as anonymous (Q16)", () => {
  const anonymous: RouteFact = { ...route, path: "trpc:router/statusPage.ts#getReport", file: "router/statusPage.ts",
    tables: ["page", "statusReport"], authenticated: false };
  const claim = { ...hypothesis, entry: anonymous.path, citedFiles: [anonymous.file],
    title: "Anonymous, unscoped read of status page reports across workspaces",
    consequence: "Any unauthenticated caller can read other tenants' reports." };
  const base = { deterministic: [], stack, repositoryId: "r1", hasDatabase: false };

  it("states what we read, keeps the model's sentence unverified, and keeps id and severity", () => {
    const [finding] = buildFindings({ ...base, routes: [anonymous], admitted: [claim] });
    expect(finding.title).toBe("Anyone can call this without signing in");
    expect(finding.consequence).toBe(
      "We read no sign-in check on trpc:router/statusPage.ts#getReport, and its query on page and statusReport is not narrowed to a caller, so the request alone decides what it reads or changes.");
    expect(`${finding.title} ${finding.consequence}`).not.toMatch(/workspace|tenant|[–—]/i);
    expect(finding.claims).toContainEqual({ claim: claim.consequence, origin: "agent", verified: false });
    expect(finding.id).toBe(`agent:missing_authorization:${anonymous.path}`);
    expect(finding.severity).toBe("WARNING"); // repository-only (2026-09-29 cap)
  });

  // Q26: the same rule on a signed-in route whose scope we read as not
  // narrowed. CORPUS-3 showed model titles written for the wrong mechanism
  // ("Anonymous, unscoped mutation...") on signed-in IDORs; say what we read.
  it("states what we read on a signed-in route whose query is not narrowed (Q26)", () => {
    const [signedIn] = buildFindings({ ...base, routes: [route], admitted: [hypothesis] });
    expect(signedIn.title).toBe("Signed-in callers are not limited to their own rows");
    expect(signedIn.consequence).toBe(
      "We read a sign-in check on /api/invoices/[id], but its query on invoices is not narrowed to the signed-in caller, so any signed-in user's request decides which rows it reads or changes.");
    expect(signedIn.claims).toContainEqual({ claim: hypothesis.consequence, origin: "agent", verified: false });
    expect(signedIn.severity).toBe("WARNING"); // repository-only (2026-09-29 cap)
    expect(signedIn.id).toBe(`agent:missing_authorization:${route.path}`);
  });

  it("keeps the model's words where identity or scope was not read", () => {
    const scopeUnread: RouteFact = { ...route, ownershipReadable: false, ownershipGap: "helper" };
    const [signedIn] = buildFindings({ ...base, routes: [scopeUnread], admitted: [hypothesis] });
    expect(signedIn.title).toBe(hypothesis.title);
    const unread: RouteFact = { ...anonymous, identityReadable: false, identityGap: "wrapper not read" };
    const [unknown] = buildFindings({ ...base, routes: [unread], admitted: [claim] });
    expect(unknown.title).toBe(claim.title);
  });
});

// Felipe (2026-09-29, delegated): three held-out sets put repository-only
// admitted findings near 5% precision, so CRITICAL requires evidence from
// outside the code: a live provider fact the finding cites (or, later, a
// reproduction). Repository-only findings cap at WARNING, to review.
describe("CRITICAL needs evidence outside the repository", () => {
  const base = { deterministic: [], stack, repositoryId: "r1", hasDatabase: false };
  it("caps a repository-only missing_authorization finding at WARNING and says why", () => {
    const [f] = buildFindings({ ...base, routes: [route], admitted: [hypothesis] });
    expect(f.severity).toBe("WARNING");
    expect(f.claims.some((c) => /only from your code/.test(c.claim))).toBe(true);
  });
  it("keeps CRITICAL when the finding cites a live provider fact", () => {
    const [f] = buildFindings({ ...base, routes: [route], admitted: [{ ...hypothesis, citedFacts: ["live:rls-off"] }],
      liveFacts: [{ id: "live:rls-off", statement: "Row level security is off on invoices." }] });
    expect(f.severity).toBe("CRITICAL");
  });
});

import { describe, expect, it } from "vitest";
import type { DashboardFinding } from "./dashboardData";
import { fixBranchName, fixDocument, fixFilePath } from "./fixPr";

const finding: DashboardFinding = {
  rowId: "row-1",
  id: "agent:missing_authorization:/api/invoices/[id]",
  title: "Any signed-in user can read another workspace's invoices",
  consequence: "A valid account is enough to retrieve other customers' billing records.",
  severity: "CRITICAL",
  confidence: "corroborated",
  attackClass: "missing_authorization",
  entry: "/api/invoices/[id]",
  file: "app/api/invoices/[id]/route.ts",
  blastRadius: "invoices",
  fixKind: "pr",
  claims: [
    { claim: "The route resolves a user but never a workspace.", origin: "routes", verified: true },
    { claim: "This looks exploitable.", origin: "agent", verified: false },
  ],
  repository: "acme/app",
  detectedAt: "2026-08-28T00:00:00Z",
  fixPrUrl: null,
  fixPrNumber: null,
};

describe("fixBranchName", () => {
  it("is a safe ref under our own namespace", () => {
    // The branch name is built from a finding id that contains slashes and
    // brackets. Passing that through unescaped would create refs GitHub rejects
    // or, worse, refs that collide with the customer's own.
    const branch = fixBranchName(finding.id);
    expect(branch.startsWith("shiplock/fix-")).toBe(true);
    expect(branch).not.toMatch(/[[\]]/);
    expect(branch.split("/")).toHaveLength(2);
  });

  it("is stable, so re-opening does not fork a second branch", () => {
    expect(fixBranchName(finding.id)).toBe(fixBranchName(finding.id));
  });
});

describe("fixFilePath", () => {
  it("writes inside .shiplock, never over the customer's own files", () => {
    expect(fixFilePath(finding.id).startsWith(".shiplock/")).toBe(true);
  });
});

describe("fixDocument", () => {
  it("carries the evidence and marks which claims are only proposed", () => {
    const doc = fixDocument(finding);
    expect(doc).toContain("The route resolves a user but never a workspace.");
    expect(doc).toContain("verified");
    expect(doc).toContain("proposed");
  });

  it("says what to change without writing the authorization logic", () => {
    // We stage the work and keep the decision with the human. A confidently
    // wrong patch to an access check is worse than no patch.
    const doc = fixDocument(finding);
    expect(doc).toContain("Narrow the query");
    expect(doc).not.toContain("```");
  });

  it("states the confidence and what it means", () => {
    const doc = fixDocument({ ...finding, confidence: "inferred" });
    expect(doc).toContain("inferred");
    expect(doc).toContain("could compensate");
  });

  it("says the default branch was not touched", () => {
    expect(fixDocument(finding)).toContain("default");
  });

  it("tells a leaked-secret finding to rotate first", () => {
    const doc = fixDocument({ ...finding, attackClass: "secret_exposure" });
    expect(doc).toContain("Rotate the credential first");
  });
});

describe("the document a reviewer actually reads", () => {
  it("keeps the blank lines markdown needs", () => {
    // The first real pull request we opened rendered as one wall of text: the
    // conditional-line filter removed every deliberate blank line too, so each
    // heading ran into its own paragraph. This body is the entire product
    // surface a reviewer sees.
    const doc = fixDocument(finding);
    expect(doc).toContain("\n\n## Where\n\n");
    expect(doc).toContain("\n\n## What to change\n\n");
    expect(doc).toMatch(/^# .+\n\n/);
  });

  it("drops a line with nothing to say, and leaves no sentinel behind", () => {
    const doc = fixDocument({ ...finding, blastRadius: null });
    expect(doc).not.toContain("Reaches:");
    expect(doc).not.toContain(String.fromCharCode(0));
  });
});

import { describe, expect, it } from "vitest";
import { guardHypotheses, judgeHypothesis, type Hypothesis, type ReconIndex } from "./attackGuard";

const recon: ReconIndex = {
  entries: new Set(["/api/invoices/[id]"]),
  files: new Set(["app/api/invoices/[id]/route.ts", "lib/db.ts"]),
  tables: new Set(["invoices", "users"]),
};

const valid: Hypothesis = {
  entry: "/api/invoices/[id]",
  attackClass: "missing_authorization",
  title: "Any signed-in user can read another workspace's invoices",
  consequence: "A valid account is enough to retrieve billing records belonging to other customers.",
  citedFiles: ["app/api/invoices/[id]/route.ts"],
  citedTables: ["invoices"],
};

describe("judgeHypothesis", () => {
  it("admits a hypothesis whose every concrete claim checks out", () => {
    expect(judgeHypothesis(valid, recon)).toEqual({ allowed: true, attackClass: "missing_authorization" });
  });

  it("refuses a route the model invented", () => {
    // The failure this exists to stop: a finding pointing at code that is not
    // there. It reads exactly like a real one and destroys trust on contact.
    const verdict = judgeHypothesis({ ...valid, entry: "/api/admin/users" }, recon);
    expect(verdict).toEqual({ allowed: false, reason: 'entry "/api/admin/users" is not in the route inventory' });
  });

  it("refuses a file we never read", () => {
    const verdict = judgeHypothesis({ ...valid, citedFiles: ["app/api/secret/route.ts"] }, recon);
    expect(verdict.allowed).toBe(false);
  });

  it("refuses a table that is not in the schema we read", () => {
    // Models are good at guessing that a billing app has a payment_methods
    // table. Guessing correctly is still guessing.
    const verdict = judgeHypothesis({ ...valid, citedTables: ["payment_methods"] }, recon);
    expect(verdict).toEqual({ allowed: false, reason: 'cited table "payment_methods" is not in the schema we read' });
  });

  it("refuses a claim with no location at all", () => {
    expect(judgeHypothesis({ ...valid, citedFiles: [] }, recon)).toEqual({ allowed: false, reason: "no file cited" });
  });

  it("refuses a vulnerability class outside the taxonomy", () => {
    const verdict = judgeHypothesis({ ...valid, attackClass: "nuclear_launch" }, recon);
    expect(verdict.allowed).toBe(false);
  });

  it("refuses markup in prose, which would reach a pull-request body", () => {
    const verdict = judgeHypothesis({ ...valid, title: "Broken <img src=x onerror=alert(1)>" }, recon);
    expect(verdict).toEqual({ allowed: false, reason: "control characters or markup in prose" });
  });

  it("refuses unbounded prose", () => {
    expect(judgeHypothesis({ ...valid, consequence: "x".repeat(401) }, recon).allowed).toBe(false);
    expect(judgeHypothesis({ ...valid, title: "x".repeat(161) }, recon).allowed).toBe(false);
  });

  it("refuses a non-object", () => {
    expect(judgeHypothesis(null as unknown as Hypothesis, recon).allowed).toBe(false);
  });
});

describe("guardHypotheses", () => {
  it("separates admitted from rejected and keeps the reasons", () => {
    const result = guardHypotheses([valid, { ...valid, entry: "/api/nope" }], recon);
    expect(result.admitted).toHaveLength(1);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0].reason).toContain("not in the route inventory");
  });

  it("treats a non-array response as a total rejection, never as zero findings", () => {
    // A model that returns prose instead of JSON must not read as "your code is
    // clean". That is the silence-as-safety failure this repo has shipped.
    const result = guardHypotheses("I could not find anything", recon);
    expect(result.admitted).toEqual([]);
    expect(result.rejected[0].reason).toBe("model did not return an array");
  });
});

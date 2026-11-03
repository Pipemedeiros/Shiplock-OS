import { describe, expect, it } from "vitest";
import { isConfirmed } from "./confirmed";

// (Felipe 2026-10-07: "prioritize accuracy"; decision 6). Only a confirmed
// issue sets the status. Measured on CORPUS-5's whole harness: agent findings
// proven with quoted lines were 71% strictly true, code-pattern findings 0 of
// 14. Everything else is "To review".
const base = { severity: "WARNING" as const, confidence: "inferred" as const, attackClass: "missing_authorization", claims: [] };
const claim = (origin: string, verified: boolean) => ({ claim: "x", origin, verified }) as never;

describe("isConfirmed", () => {
  it("confirms a finding the agent proved with quoted lines", () => {
    expect(isConfirmed({ ...base, claims: [claim("routes", true), claim("agent", true)] })).toBe(true);
  });
  it("confirms a replica proof and a live provider fact", () => {
    expect(isConfirmed({ ...base, confidence: "proven" })).toBe(true);
    expect(isConfirmed({ ...base, claims: [claim("live", true)] })).toBe(true);
  });
  it("confirms a committed live credential, which is direct evidence", () => {
    expect(isConfirmed({ ...base, severity: "CRITICAL", attackClass: "committed_secret" })).toBe(true);
  });
  it("leaves code-pattern findings and unproven proposals to review", () => {
    expect(isConfirmed({ ...base, attackClass: "committed_secret" })).toBe(false);
    expect(isConfirmed({ ...base, claims: [claim("routes", true), claim("agent", false)] })).toBe(false);
    expect(isConfirmed({ ...base, attackClass: "permission_gap", claims: [claim("routes", true), claim("routes", true)] })).toBe(false);
  });
});

// An app with no sign-in whose own code says it is open by design
// has no other account to reach; whether it should be open is the founder's
// call. The finding stays, with quoted proof, as To review.
describe("open by design", () => {
  it("does not confirm a proven open-access finding in an app open by design", async () => {
    const { buildFindings } = await import("./findings");
    const route = { path: "/api/farm", file: "src/actions/pac.ts", tables: ["farm"], authenticated: false, identityReadable: true,
      machineGated: false, ownershipFiltered: false, ownershipReadable: true, usesServiceRole: true, serviceRoleReadable: true, via: [] };
    const input = (open?: { file: string; line: number; reason: string }) => buildFindings({
      admitted: [{ entry: "/api/farm", attackClass: "missing_authentication", title: "t", consequence: "Anyone can edit any farm.",
        citedFiles: ["src/actions/pac.ts"], citedTables: ["farm"], provenStatement: true,
        proof: [{ role: "reach", path: "src/actions/pac.ts", line: 95, quote: "export async function updatePacField(" }] }],
      deterministic: [], routes: [route as never], stack: { tools: [], authUnknown: true, databaseUnknown: false } as never,
      repositoryId: "r", hasDatabase: false, openByDesign: open });
    const [plain] = input();
    expect(isConfirmed(plain)).toBe(true);
    const [open] = input({ file: "src/lib/demo.ts", line: 2, reason: "sets a fixed demo identity (DEMO_FARMER_ID)" });
    expect(isConfirmed(open)).toBe(false);
    expect(open.claims).toContainEqual({ origin: "routes", verified: true,
      claim: "This app signs no one in by design (src/lib/demo.ts:2 sets a fixed demo identity (DEMO_FARMER_ID)), so there is no other account to reach. Anyone who can reach it can do this; whether it should be open is your call." });
    expect(open.severity).toBe(plain.severity);
  });

  it("leaves a committed secret confirmed in the same app", () => {
    expect(isConfirmed({ ...base, severity: "CRITICAL", attackClass: "committed_secret",
      claims: [{ claim: "This app signs no one in by design (x), so", origin: "routes", verified: true }] as never })).toBe(true);
  });
});

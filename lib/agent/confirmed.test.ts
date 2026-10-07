import { describe, expect, it } from "vitest";
import { isConfirmed } from "./confirmed";

// A1 (Felipe 2026-10-07: "prioritize accuracy"; decision 6). Only a confirmed
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

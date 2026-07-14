import { describe, expect, it } from "vitest";
import { classifyJwks } from "./sessionAudit";

describe("classifyJwks", () => {
  it("flags legacy shared-secret signing when no asymmetric keys are published", () => {
    const p = classifyJwks([]);
    expect(p.ok).toBe(false);
    expect(p.severity).toBe("WARNING");
  });

  it("passes when asymmetric (EC/RSA/OKP) keys are present", () => {
    for (const kty of ["RSA", "EC", "OKP"]) {
      const p = classifyJwks([{ kty }]);
      expect(p.ok).toBe(true);
      expect(p.severity).toBe("INFO");
    }
  });

  it("treats symmetric-only (oct) keys as legacy", () => {
    expect(classifyJwks([{ kty: "oct" }]).ok).toBe(false);
  });

  it("returns an informational unknown when keys can't be read", () => {
    const p = classifyJwks(null);
    expect(p.ok).toBe(true);
    expect(p.title).toMatch(/could not determine/i);
  });
});

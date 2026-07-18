import { describe, expect, it } from "vitest";
import { generateToken, hashToken, isTokenShaped } from "./apiTokens";

describe("api tokens", () => {
  it("generates a prefixed token and a matching hash", () => {
    const { raw, hash } = generateToken();
    expect(raw.startsWith("shiplock_pat_")).toBe(true);
    expect(hash).toBe(hashToken(raw));
    expect(hash).toMatch(/^[0-9a-f]{64}$/); // sha256 hex
  });

  it("generates distinct tokens", () => {
    expect(generateToken().raw).not.toBe(generateToken().raw);
  });

  it("recognizes shaped vs unshaped tokens", () => {
    expect(isTokenShaped(generateToken().raw)).toBe(true);
    expect(isTokenShaped("nope")).toBe(false);
    expect(isTokenShaped("shiplock_pat_short")).toBe(false);
    expect(isTokenShaped("")).toBe(false);
  });
});

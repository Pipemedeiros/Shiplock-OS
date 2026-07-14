import { describe, expect, it } from "vitest";
import { GUARDRAILS } from "./guardrails";

describe("GUARDRAILS", () => {
  it("covers the uncatchable categories with non-empty prompts", () => {
    expect(GUARDRAILS.length).toBeGreaterThanOrEqual(5);
    for (const g of GUARDRAILS) {
      expect(g.id).toBeTruthy();
      expect(g.surface).toBeTruthy();
      expect(g.why.length).toBeGreaterThan(20);
      expect(g.prompts.length).toBeGreaterThan(0);
      for (const p of g.prompts) expect(p.length).toBeGreaterThan(20);
    }
  });

  it("has unique ids", () => {
    const ids = GUARDRAILS.map((g) => g.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("includes the session/JWT category", () => {
    expect(GUARDRAILS.some((g) => g.id === "session-jwt")).toBe(true);
  });
});

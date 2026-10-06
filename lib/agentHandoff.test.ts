import { describe, expect, it } from "vitest";
import { agentFixPrompt } from "./agentHandoff";

// Felipe 2026-10-06: easy for the customer's agent to operate. One copyable
// instruction hands a finding to the agent over ShipLock's MCP tools; the
// agent proposes a change the customer reviews, and nothing merges itself.
describe("agent fix prompt", () => {
  const prompt = agentFixPrompt({ id: "f-123", title: "Orders are readable by any signed-in user", repository: "acme/app", fixKind: "pr" });

  it("names the finding and the repository", () => {
    expect(prompt).toContain("f-123");
    expect(prompt).toContain("acme/app");
    expect(prompt).toContain("Orders are readable by any signed-in user");
  });

  it("tells the agent which ShipLock tools to call, in order", () => {
    expect(prompt.indexOf("get_security_context")).toBeLessThan(prompt.indexOf("get_fix"));
  });

  it("keeps the guardrails and leaves the merge to the person", () => {
    expect(prompt).toMatch(/keep every guardrail/i);
    expect(prompt).toMatch(/do not merge/i);
  });

  it("says an authorization decision is the person's, not the agent's", () => {
    const manual = agentFixPrompt({ id: "f-9", title: "t", repository: "acme/app", fixKind: "manual" });
    expect(manual).toMatch(/propose/i);
    expect(manual).toMatch(/decide/i);
  });

  it("uses no dashes", () => {
    expect(prompt).not.toMatch(/[–—]| - /);
  });
});

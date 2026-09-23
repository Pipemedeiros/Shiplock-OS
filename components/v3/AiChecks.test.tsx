import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AiChecks, aiStateLabel } from "./AiChecks";
import type { AiCheck } from "@/lib/intelligence/activity";

const check = (state: AiCheck["state"], extra: Partial<AiCheck> = {}): AiCheck => ({ taskId: state, repository: "acme/app",
  kind: "pr", pullRequest: 7, commit: "a".repeat(40), state, createdAt: "2026-09-23T10:00:00Z", expiresAt: "2026-09-23T20:00:00Z", answer: null, ...extra });

describe("AiChecks (10B-2d)", () => {
  it("labels every unanswered state as not checked", () => {
    for (const state of ["pending", "expired", "withdrawn", "unavailable"] as const) {
      expect(aiStateLabel[state]).toMatch(/not checked/i);
    }
    expect(aiStateLabel.proposal).not.toMatch(/clean|secure|passed/i);
  });

  it("renders checks with their PR and states, and never says clean", () => {
    const html = renderToStaticMarkup(<AiChecks activity={{ available: true, paused: null,
      checks: [check("pending"), check("expired", { kind: "deep", pullRequest: null })] }} />);
    expect(html).toContain("#7");
    expect(html).toContain("Weekly deep scan");
    expect(html).toContain("Waiting for your AI");
    expect(html).not.toMatch(/clean|secure/i);
  });

  it("shows an answer's summary, cited lines, and proposed files as the AI's claim, not a verdict (10B-3a)", () => {
    const html = renderToStaticMarkup(<AiChecks activity={{ available: true, paused: null, checks: [check("proposal", {
      answer: { summary: "Disable production source maps.", citations: [{ path: "next.config.ts", startLine: 2, endLine: 3 }],
        editedFiles: ["next.config.ts"] } })] }} />);
    expect(html).toContain("Disable production source maps.");
    expect(html).toContain("next.config.ts:2-3");
    expect(html).toContain("Proposed change to next.config.ts");
    expect(html).toContain("Your AI says");
    expect(html).not.toMatch(/clean|secure/i);
    // Each PR needs its own click (10B-3b).
    expect(html).toContain("Open a pull request");
  });

  it("offers no pull request for a finding that needs your judgment", () => {
    const html = renderToStaticMarkup(<AiChecks activity={{ available: true, paused: null, checks: [check("needs_human", {
      answer: { summary: "Orders have no owner check.", citations: [{ path: "a.ts", startLine: 1, endLine: 1 }], editedFiles: [] } })] }} />);
    expect(html).not.toContain("Open a pull request");
  });

  it("says why new checks are paused, and admits when it cannot read state", () => {
    expect(renderToStaticMarkup(<AiChecks activity={{ available: true, paused: "budget", checks: [] }} />))
      .toContain("monthly token limit");
    expect(renderToStaticMarkup(<AiChecks activity={{ available: true, paused: "not_connected", checks: [] }} />))
      .toContain("Settings");
    expect(renderToStaticMarkup(<AiChecks activity={{ available: false }} />)).toContain("could not load");
  });
});

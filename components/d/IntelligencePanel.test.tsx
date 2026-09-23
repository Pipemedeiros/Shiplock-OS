import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { IntelligenceApprovalView, defaultDraft } from "./IntelligencePanel";

const handlers = () => ({ onChange: vi.fn(), onApprove: vi.fn(), onRevoke: vi.fn() });
const approved = { state: "approved", host: "codex", deepScan: "weekly", prScan: "daily", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, approvedAt: "2026-09-23T00:00:00Z", budgetEnforcement: "advisory",
  pullRequests: "each_needs_a_click" } as const;
const html = (props: Partial<Parameters<typeof IntelligenceApprovalView>[0]> = {}) => renderToStaticMarkup(
  IntelligenceApprovalView({ connection: { state: "none" }, draft: defaultDraft, busy: false, error: "", ...handlers(), ...props }));

describe("IntelligencePanel (10B-2b)", () => {
  it("offers every approved host and cadence and says PRs always need a click", () => {
    const out = html();
    for (const label of ["Claude Code", "Codex", "ChatGPT", "Your own API key", "Every PR", "Every 2 days", "Daily"]) {
      expect(out).toContain(label);
    }
    expect(out).toContain("Every pull request still needs your click");
    expect(out).toContain("not connected");
    // PR scans are tied to PRs; there is no per-deploy cadence.
    expect(out).not.toContain("per_deploy");
  });

  it("is honest that pull-host budgets are advisory and agent setup is not live", () => {
    const out = html();
    expect(out).toContain("your agent spends its own allowance");
    expect(out).toContain("Agent setup is not available yet");
    expect(out).not.toContain("npx");
    expect(html({ draft: { ...defaultDraft, host: "api" } })).toContain("API key mode is not available yet");
  });

  it("cannot approve without proposal consent", () => {
    expect(html()).toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/);
    expect(html({ draft: { ...defaultDraft, allowProposals: true } })).not.toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/);
  });

  it("shows the current approval with a revoke control", () => {
    const out = html({ connection: approved });
    expect(out).toContain("approved");
    expect(out).toContain("Revoke");
    expect(html({ connection: { ...approved, state: "revoked" } })).toContain("revoked");
  });
});

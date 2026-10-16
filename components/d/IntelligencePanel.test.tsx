import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { IntelligenceApprovalView, defaultDraft } from "./IntelligencePanel";

const handlers = () => ({ onChange: vi.fn(), onApprove: vi.fn(), onRevoke: vi.fn() });
const approved = { state: "approved", host: "codex", deepScan: "weekly", prScan: "daily", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, approvedAt: "2026-09-23T00:00:00Z",
  pullRequests: "each_needs_a_click", monthReportedTokens: 12000 } as const;
const html = (props: Partial<Parameters<typeof IntelligenceApprovalView>[0]> = {}) => renderToStaticMarkup(
  IntelligenceApprovalView({ connection: { state: "none" }, draft: defaultDraft, busy: false, error: "", ...handlers(), ...props }));

describe("IntelligencePanel (10B-2b)", () => {
  it("offers every approved host and cadence and says PRs need a click unless agent pull requests are on", () => {
    const out = html();
    for (const label of ["Claude Code", "Codex", "ChatGPT", "Every PR", "Every 2 days", "Daily"]) {
      expect(out).toContain(label);
    }
    // ShipLock runs no model (Felipe, 2026-10-01): an API key is not a host.
    expect(out).not.toContain("API key");
    expect(out).not.toContain('type="password"');
    expect(out).toContain("Pull requests need your click unless you");
    expect(out).toContain("not connected");
    // PR scans are tied to PRs; there is no per-deploy cadence.
    expect(out).not.toContain("per_deploy");
  });

  it("is honest that pull-host budgets are advisory and agent setup is not live", () => {
    const out = html();
    expect(out).toContain("your agent spends its own allowance");
    // Every account can connect its own agent over MCP (Felipe 2026-09-23).
    // Until shiplock-mcp is published, Claude Code connects to the hosted
    // endpoint (G1) and nothing names the unpublished package.
    expect(out).toContain("Create a token");
    expect(out).not.toContain("npx");
  });

  it("tells a retired API-key approval to choose an agent; no stored key is offered (100 dropped them)", () => {
    const retired = html({ connection: { state: "retired" } });
    expect(retired).toContain("API key mode was retired");
    expect(retired).toContain("not connected");
    expect(retired).not.toContain("Remove key");
  });

  it("cannot approve without proposal consent", () => {
    expect(html()).toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/);
    expect(html({ draft: { ...defaultDraft, allowProposals: true } })).not.toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/);
  });

  it("shows agent-reported monthly usage as unverified, and says when the limit paused new work", () => {
    expect(html({ connection: approved })).toContain("12,000 of 1,000,000 tokens this month, as reported by your agent");
    expect(html({ connection: { ...approved, monthReportedTokens: 1_000_000 } })).toContain("New AI checks are paused until next month");
  });

  it("shows the current approval with a revoke control", () => {
    const out = html({ connection: approved });
    expect(out).toContain("approved");
    expect(out).toContain("Revoke");
    expect(html({ connection: { ...approved, state: "revoked" } })).toContain("revoked");
  });
});

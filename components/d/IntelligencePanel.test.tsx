import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { IntelligenceApprovalView, RemoveKeyView, defaultDraft } from "./IntelligencePanel";

const handlers = () => ({ onChange: vi.fn(), onApprove: vi.fn(), onRevoke: vi.fn(), onRemoveKey: vi.fn() });
const approved = { state: "approved", host: "codex", deepScan: "weekly", prScan: "daily", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, approvedAt: "2026-09-23T00:00:00Z",
  pullRequests: "each_needs_a_click", monthReportedTokens: 12000 } as const;
const html = (props: Partial<Parameters<typeof IntelligenceApprovalView>[0]> = {}) => renderToStaticMarkup(
  IntelligenceApprovalView({ connection: { state: "none" }, apiKey: { stored: false }, draft: defaultDraft, busy: false, error: "", ...handlers(), ...props }));

describe("IntelligencePanel (10B-2b)", () => {
  it("offers every approved host and cadence and says PRs always need a click", () => {
    const out = html();
    for (const label of ["Claude Code", "Codex", "ChatGPT", "Every PR", "Every 2 days", "Daily"]) {
      expect(out).toContain(label);
    }
    // ShipLock runs no model (Felipe, 2026-10-01): an API key is not a host.
    expect(out).not.toContain("API key");
    expect(out).not.toContain('type="password"');
    expect(out).toContain("Every pull request still needs your click");
    expect(out).toContain("not connected");
    // PR scans are tied to PRs; there is no per-deploy cadence.
    expect(out).not.toContain("per_deploy");
  });

  it("is honest that pull-host budgets are advisory and agent setup is not live", () => {
    const out = html();
    expect(out).toContain("your agent spends its own allowance");
    // Every account can connect its own agent over MCP (Felipe 2026-09-23).
    // Until shiplock-mcp is published the panel says so instead of offering setup.
    expect(out).toContain("opens once the ShipLock MCP package is published");
    expect(out).not.toContain("npx");
  });

  it("tells a retired API-key approval to choose an agent, and offers to erase a stored key", () => {
    const retired = html({ connection: { state: "retired" } });
    expect(retired).toContain("API key mode was retired");
    expect(retired).toContain("not connected");
    const stored = html({ apiKey: { stored: true, hint: "Qr_7", savedAt: "2026-09-23T00:00:00Z" } });
    expect(stored).toContain("ending in Qr_7");
    expect(stored).toContain("no longer used");
    expect(stored).toContain("Remove key");
    expect(stored).not.toContain("sk-ant");
    expect(html()).not.toContain("Remove key");
  });

  it("asks once more before erasing a stored key, which cannot be undone", () => {
    const first = renderToStaticMarkup(RemoveKeyView({ confirming: false, busy: false, onAsk: vi.fn(), onConfirm: vi.fn(), onCancel: vi.fn() }));
    expect(first).toContain("Remove key");
    expect(first).not.toContain("Cancel");
    const second = renderToStaticMarkup(RemoveKeyView({ confirming: true, busy: false, onAsk: vi.fn(), onConfirm: vi.fn(), onCancel: vi.fn() }));
    expect(second).toContain("Remove for good");
    expect(second).toContain("Cancel");
    expect(second).toContain('role="group"');
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

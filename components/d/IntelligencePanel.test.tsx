import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { IntelligenceApprovalView, defaultDraft } from "./IntelligencePanel";

const handlers = () => ({ onChange: vi.fn(), onApprove: vi.fn(), onRevoke: vi.fn(), onSaveKey: vi.fn(), onRemoveKey: vi.fn() });
const approved = { state: "approved", host: "codex", deepScan: "weekly", prScan: "daily", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, approvedAt: "2026-09-23T00:00:00Z", budgetEnforcement: "advisory",
  pullRequests: "each_needs_a_click", monthReportedTokens: 12000 } as const;
const html = (props: Partial<Parameters<typeof IntelligenceApprovalView>[0]> = {}) => renderToStaticMarkup(
  IntelligenceApprovalView({ connection: { state: "none" }, apiKey: { stored: false }, draft: defaultDraft, busy: false, error: "", ...handlers(), ...props }));

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
    expect(html({ draft: { ...defaultDraft, host: "api" } })).toContain("ShipLock does not run tasks on it yet");
  });

  it("offers a key field only for API-key mode and never shows more than the saved key's last 4 characters (10B-2e)", () => {
    expect(html()).not.toContain('type="password"');
    const api = { ...defaultDraft, host: "api" as const };
    expect(html({ draft: api })).toContain('type="password"');
    expect(html({ draft: api })).toContain("Save key");
    const saved = html({ draft: api, apiKey: { stored: true, hint: "Qr_7", savedAt: "2026-09-23T00:00:00Z" } });
    expect(saved).toContain("Key ending in Qr_7 is saved");
    expect(saved).toContain("Remove key");
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

import { beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
const maybeSingle = vi.hoisted(() => vi.fn());
const eq = vi.hoisted(() => vi.fn(() => ({ maybeSingle })));
const select = vi.hoisted(() => vi.fn(() => ({ eq })));
const from = vi.hoisted(() => vi.fn(() => ({ select })));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc, from }) }));

import { ConnectionApproval, approveIntelligenceConnection, getIntelligenceConnection, revokeIntelligenceConnection } from "./connection";

beforeEach(() => { rpc.mockReset(); maybeSingle.mockReset(); });

const valid = { host: "claude-code", deepScan: "weekly", prScan: "daily", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, allowProposals: true };

describe("intelligence connection approval (10B-2b)", () => {
  it("accepts one bounded standing approval and requires explicit proposal consent", () => {
    expect(ConnectionApproval.parse(valid)).toEqual(valid);
    expect(() => ConnectionApproval.parse({ ...valid, allowProposals: false })).toThrow();
    expect(() => ConnectionApproval.parse({ ...valid, host: "gemini" })).toThrow();
    expect(() => ConnectionApproval.parse({ ...valid, prScan: "hourly" })).toThrow();
    expect(() => ConnectionApproval.parse({ ...valid, prScan: "per_deploy" })).toThrow();
    expect(() => ConnectionApproval.parse({ ...valid, runTokenBudget: 500 })).toThrow();
    expect(() => ConnectionApproval.parse({ ...valid, monthlyTokenBudget: 10000 })).toThrow();
    // A standing approval can never carry PR or merge authority.
    expect(() => ConnectionApproval.parse({ ...valid, allowPullRequests: true })).toThrow();
  });

  it("persists through the service-only RPC", async () => {
    rpc.mockResolvedValue({ data: "2026-09-23T00:00:00Z", error: null });
    await approveIntelligenceConnection("u1", ConnectionApproval.parse(valid));
    expect(rpc).toHaveBeenCalledWith("approve_intelligence_connection", { p_user: "u1", p_host: "claude-code",
      p_deep: "weekly", p_pr: "daily", p_run: 50000, p_month: 1000000 });
    rpc.mockResolvedValue({ data: null, error: { message: "down" } });
    await expect(approveIntelligenceConnection("u1", ConnectionApproval.parse(valid))).rejects.toThrow();
  });

  it("reads the current approval and labels what a pull host can and cannot enforce", async () => {
    rpc.mockResolvedValue({ data: 12000, error: null });
    maybeSingle.mockResolvedValue({ data: { host: "codex", deep_scan_cadence: "weekly", pr_scan_cadence: "every_pr",
      run_token_budget: 20000, monthly_token_budget: 500000, approved_at: "2026-09-23T00:00:00Z", revoked_at: null }, error: null });
    expect(await getIntelligenceConnection("u1")).toEqual({ state: "approved", host: "codex", deepScan: "weekly",
      prScan: "every_pr", runTokenBudget: 20000, monthlyTokenBudget: 500000, approvedAt: "2026-09-23T00:00:00Z",
      pullRequests: "each_needs_a_click", monthReportedTokens: 12000 });
    expect(rpc).toHaveBeenCalledWith("intelligence_month_usage", { p_user: "u1" });
    maybeSingle.mockResolvedValue({ data: { host: "api", deep_scan_cadence: "off", pr_scan_cadence: "off",
      run_token_budget: 20000, monthly_token_budget: 500000, approved_at: "2026-09-23T00:00:00Z", revoked_at: "2026-09-24T00:00:00Z" }, error: null });
    // API-key mode is retired (Felipe, 2026-10-01): its row is no approval.
    expect(await getIntelligenceConnection("u1")).toEqual({ state: "retired" });
    maybeSingle.mockResolvedValue({ data: null, error: null });
    expect(await getIntelligenceConnection("u1")).toEqual({ state: "none" });
    maybeSingle.mockResolvedValue({ data: null, error: { message: "down" } });
    await expect(getIntelligenceConnection("u1")).rejects.toThrow();
  });

  it("revokes and reports cancelled pending tasks", async () => {
    rpc.mockResolvedValue({ data: 2, error: null });
    expect(await revokeIntelligenceConnection("u1")).toEqual({ cancelledTasks: 2 });
    expect(rpc).toHaveBeenCalledWith("revoke_intelligence_connection", { p_user: "u1" });
  });
});

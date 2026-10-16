import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const authMcp = vi.fn();
const profile = vi.fn();
const runMonitoringPass = vi.fn();
const getFixFindings = vi.fn();
const runFixPr = vi.fn();
const resolveRepairTarget = vi.fn();
const requestAgentRepairAction = vi.fn();

vi.mock("@/lib/mcpAuth", () => ({ authMcp }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({ select: () => ({ eq: () => ({ maybeSingle: profile }) }) }),
  }),
}));
vi.mock("@/lib/monitoring/run", () => ({ runMonitoringPass }));
vi.mock("@/lib/fixes/findings", () => ({ getFixFindings }));
vi.mock("@/lib/fixes/prRun", () => ({ runFixPr }));
vi.mock("@/lib/fixes/repairTarget", () => ({ resolveRepairTarget }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestAgentRepairAction, AGENT_PRS_OFF: "agent_prs_off" }));

const { POST: scan } = await import("./scan/route");
const { POST: openPr } = await import("./fix/pr/route");

describe("MCP approval boundary", () => {
  beforeEach(() => {
    authMcp.mockReset().mockResolvedValue({ userId: "user-1" });
    profile.mockReset().mockResolvedValue({ data: {
      id: "user-1", email: "user@example.invalid", monitoring_enabled: true,
      monitored_project_url: "https://example.invalid", monitored_anon_key_encrypted: "ciphertext",
    } });
    runMonitoringPass.mockReset().mockResolvedValue({ newFindingsCount: 0 });
    getFixFindings.mockReset().mockResolvedValue([{
      id: "github:one", source: "github", title: "Test finding",
      severity: "WARNING", fix: "Review this fix", filePath: "app/route.ts",
    }]);
    runFixPr.mockReset().mockResolvedValue({ url: "https://github.com/example/pull/1" });
    resolveRepairTarget.mockReset();
    requestAgentRepairAction.mockReset();
  });

  it("does not run a monitoring scan from a PAT before durable admission exists", async () => {
    const response = await scan(new NextRequest("https://shiplock.dev/api/mcp/scan", { method: "POST" }));
    expect(response.status).toBe(403);
    expect(runMonitoringPass).not.toHaveBeenCalled();
  });

  const ask = (body: unknown = { findingId: "agent:one" }) => openPr(new NextRequest("https://shiplock.dev/api/mcp/fix/pr", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  }));

  // 103 (Felipe 2026-10-15): the customer's agent may ask for the click's PR
  // only where the customer turned agent pull requests on; either way the
  // request is a queued receipt, never a direct GitHub write.
  it("refuses a PAT where the customer has not turned agent pull requests on", async () => {
    resolveRepairTarget.mockResolvedValue({ ok: true, target: { action: "risk-fix-pr", repositoryId: "repo-1", findingId: "agent:one" } });
    requestAgentRepairAction.mockRejectedValue(new Error("agent_prs_off"));
    const response = await ask();
    expect(response.status).toBe(403);
    expect((await response.json()).error).toMatch(/Settings, Agent pull requests/);
    expect(runFixPr).not.toHaveBeenCalled();
  });

  it("queues the click's receipted repair where it is on, and never writes to GitHub itself", async () => {
    resolveRepairTarget.mockResolvedValue({ ok: true, target: { action: "risk-fix-pr", repositoryId: "repo-1", findingId: "agent:one" } });
    requestAgentRepairAction.mockResolvedValue("receipt-1");
    const response = await ask();
    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({ receiptId: "receipt-1", status: "queued" });
    expect(resolveRepairTarget).toHaveBeenCalledWith("user-1", { lane: "risk", findingId: "agent:one" });
    expect(requestAgentRepairAction).toHaveBeenCalledWith({ userId: "user-1", repositoryId: "repo-1", findingId: "agent:one" });
    expect(runFixPr).not.toHaveBeenCalled();
  });

  it("opens nothing for a decision about authorization, and ignores a supplied edit", async () => {
    resolveRepairTarget.mockResolvedValue({ ok: false, code: "manual" });
    expect((await ask({ findingId: "agent:one", editedContent: "anything" })).status).toBe(409);
    expect(requestAgentRepairAction).not.toHaveBeenCalled();
  });
});

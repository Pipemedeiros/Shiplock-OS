import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const authMcp = vi.fn();
const profile = vi.fn();
const runMonitoringPass = vi.fn();
const getFixFindings = vi.fn();
const runFixPr = vi.fn();

vi.mock("@/lib/mcpAuth", () => ({ authMcp }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({ select: () => ({ eq: () => ({ maybeSingle: profile }) }) }),
  }),
}));
vi.mock("@/lib/monitoring/run", () => ({ runMonitoringPass }));
vi.mock("@/lib/fixes/findings", () => ({ getFixFindings }));
vi.mock("@/lib/fixes/prRun", () => ({ runFixPr }));

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
  });

  it("does not run a monitoring scan from a PAT before durable admission exists", async () => {
    const response = await scan(new NextRequest("https://shiplock.dev/api/mcp/scan", { method: "POST" }));
    expect(response.status).toBe(403);
    expect(runMonitoringPass).not.toHaveBeenCalled();
  });

  it("does not open a PR from a PAT without a separate approval receipt", async () => {
    const response = await openPr(new NextRequest("https://shiplock.dev/api/mcp/fix/pr", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ findingId: "github:one", editedContent: "reviewed" }),
    }));
    expect(response.status).toBe(403);
    expect(runFixPr).not.toHaveBeenCalled();
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

// 3F-C2d-3: the Risks-board click admits a receipt; the worker opens the PR.
const mocks = vi.hoisted(() => ({ pro: vi.fn(), findings: vi.fn(), repo: vi.fn(), request: vi.fn(), github: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/agent/dashboardData", () => ({ getOpenFindings: mocks.findings }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestRepairAction: mocks.request }));
vi.mock("@/lib/deep/github", () => ({ openPullRequest: mocks.github, getInstallationToken: mocks.github }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { eq: () => chain, maybeSingle: mocks.repo };
  return { select: () => chain };
} }) }));

import { POST } from "./route";

const post = (body: unknown) => POST(new Request("https://shiplock.dev/api/fix/pr", { method: "POST", headers: { origin: "https://shiplock.dev" }, body: JSON.stringify(body) }));
const finding = { id: "agent:idor", repository: "acme/app", fixKind: "pr", fixPrUrl: null };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.findings.mockResolvedValue([finding]);
  mocks.repo.mockResolvedValue({ data: { id: "repo-1" } });
  mocks.request.mockResolvedValue("receipt-1");
});

describe("POST /api/fix/pr", () => {
  it("admits a receipt for the stored finding and returns 202 without touching GitHub", async () => {
    const res = await post({ findingId: "agent:idor" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ receiptId: "receipt-1", status: "queued" });
    expect(mocks.request).toHaveBeenCalledWith({ userId: "u1", repositoryId: "repo-1", action: "risk-fix-pr", findingId: "agent:idor", editedContent: null });
    expect(mocks.github).not.toHaveBeenCalled();
  });

  it("tells the customer when the daily fix limit is reached (3H-2)", async () => {
    mocks.request.mockRejectedValue(new Error("repair_quota_reached"));
    const res = await post({ findingId: "agent:idor" });
    expect(res.status).toBe(429);
    expect((await res.json()).error).toMatch(/30 fixes in the last 24 hours/);
  });

  it("returns an already-open PR without a new receipt", async () => {
    mocks.findings.mockResolvedValue([{ ...finding, fixPrUrl: "https://github.com/acme/app/pull/3" }]);
    expect(await (await post({ findingId: "agent:idor" })).json()).toEqual({ url: "https://github.com/acme/app/pull/3", alreadyOpen: true });
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it.each([
    ["an unknown finding", () => mocks.findings.mockResolvedValue([]), 404],
    ["an architecture decision", () => mocks.findings.mockResolvedValue([{ ...finding, fixKind: "manual" }]), 409],
    ["an unselected repository", () => mocks.repo.mockResolvedValue({ data: null }), 409],
  ])("refuses %s before admitting anything", async (_name, arrange, status) => {
    arrange();
    expect((await post({ findingId: "agent:idor" })).status).toBe(status);
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it("requires a signed-in account", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await post({ findingId: "agent:idor" })).status).toBe(401);
  });
});

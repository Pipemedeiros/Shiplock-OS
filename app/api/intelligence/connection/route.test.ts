import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), get: vi.fn(), approve: vi.fn(), revoke: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/intelligence/connection", async (original) => ({
  ...(await original<typeof import("@/lib/intelligence/connection")>()),
  getIntelligenceConnection: mocks.get, approveIntelligenceConnection: mocks.approve,
  revokeIntelligenceConnection: mocks.revoke,
}));

import { DELETE, GET, POST } from "./route";

const url = "https://shiplock.dev/api/intelligence/connection";
const approval = { host: "codex", deepScan: "weekly", prScan: "every_2_days", runTokenBudget: 50000,
  monthlyTokenBudget: 1000000, allowProposals: true };
const post = (body: unknown, origin = "https://shiplock.dev") => new Request(url, { method: "POST",
  headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });

beforeEach(() => { vi.clearAllMocks(); mocks.user.mockResolvedValue({ userId: "u1", email: null }); });

describe("/api/intelligence/connection (10B-2b)", () => {
  it("requires a signed-in account", async () => {
    mocks.user.mockResolvedValue(null);
    expect((await GET()).status).toBe(403);
    expect((await POST(post(approval))).status).toBe(403);
    expect((await DELETE(new Request(url, { method: "DELETE", headers: { origin: "https://shiplock.dev" } }))).status).toBe(403);
    expect(mocks.approve).not.toHaveBeenCalled();
  });

  it("reads the caller's approval without caching", async () => {
    mocks.get.mockResolvedValue({ state: "none" });
    const response = await GET();
    expect(await response.json()).toEqual({ state: "none" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mocks.get).toHaveBeenCalledWith("u1");
  });

  it("refuses cross-site or malformed approvals before writing", async () => {
    expect((await POST(post(approval, "https://evil.example"))).status).toBe(403);
    expect((await POST(post({ ...approval, allowProposals: false }))).status).toBe(400);
    expect((await POST(post({ ...approval, allowPullRequests: true }))).status).toBe(400);
    expect((await POST(new Request(url, { method: "POST", headers: { origin: "https://shiplock.dev" }, body: "x" }))).status).toBe(415);
    expect((await DELETE(new Request(url, { method: "DELETE", headers: { origin: "https://evil.example" } }))).status).toBe(403);
    expect(mocks.approve).not.toHaveBeenCalled();
    expect(mocks.revoke).not.toHaveBeenCalled();
  });

  it("approves, then revokes, for the caller only", async () => {
    mocks.get.mockResolvedValue({ state: "approved" });
    const approved = await POST(post(approval));
    expect(approved.status).toBe(200);
    expect(mocks.approve).toHaveBeenCalledWith("u1", approval);
    mocks.revoke.mockResolvedValue({ cancelledTasks: 1 });
    const revoked = await DELETE(new Request(url, { method: "DELETE", headers: { origin: "https://shiplock.dev" } }));
    expect(await revoked.json()).toEqual({ ok: true, cancelledTasks: 1 });
    expect(mocks.revoke).toHaveBeenCalledWith("u1");
  });

  it("fails closed when storage is unavailable", async () => {
    mocks.approve.mockRejectedValue(new Error("connection_unwritable"));
    expect((await POST(post(approval))).status).toBe(503);
  });
});

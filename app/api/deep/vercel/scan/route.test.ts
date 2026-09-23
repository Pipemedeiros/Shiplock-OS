import { describe, it, expect, vi, beforeEach } from "vitest";

const requireProUserMock = vi.fn();
const singleMock = vi.fn();
const runVercelEnvAuditMock = vi.fn();
const recheckMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/deep/vercelRun", () => ({ runVercelEnvAudit: runVercelEnvAuditMock }));
vi.mock("@/lib/jobs/manualRecheck", () => ({ queueCustomerRecheck: recheckMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({ select: () => ({ eq: () => ({ single: singleMock }) }) }),
  }),
}));

const { POST } = await import("./route");

describe("POST /api/deep/vercel/scan", () => {
  beforeEach(() => {
    requireProUserMock.mockReset();
    singleMock.mockReset();
    runVercelEnvAuditMock.mockReset();
    recheckMock.mockReset().mockResolvedValue("job-1");
  });

  it("returns 403 when the caller is not Pro", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await POST(new Request("https://shiplock.dev/api/deep/vercel/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(res.status).toBe(403);
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
  });

  it("returns 400 when Vercel is not connected (no stored token)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: null, vercel_team_id: null } });
    const res = await POST(new Request("https://shiplock.dev/api/deep/vercel/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(res.status).toBe(400);
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
  });

  it("queues a durable recheck instead of auditing in the request (3F-C2c-5)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: "enc", vercel_connection_epoch: "e".repeat(64), vercel_team_id: "t1" } });

    const res = await POST(new Request("https://shiplock.dev/api/deep/vercel/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ ok: true, status: "queued" });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(recheckMock).toHaveBeenCalledWith("u1", "vercel");
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
  });

  it("returns 503 with a generic message when the recheck cannot be queued", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: "enc", vercel_connection_epoch: "e".repeat(64), vercel_team_id: null } });
    recheckMock.mockRejectedValue(new Error("a very specific internal error"));

    const res = await POST(new Request("https://shiplock.dev/api/deep/vercel/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    const body = await res.json();
    expect(res.status).toBe(503);
    expect(body.error).toBe("The recheck could not be queued. Try again.");
    expect(JSON.stringify(body)).not.toContain("internal error");
  });

  it("returns 400 when a stored token has no valid connection epoch (2D)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: "enc", vercel_connection_epoch: null, vercel_team_id: null } });
    const res = await POST(new Request("https://shiplock.dev/api/deep/vercel/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(res.status).toBe(400);
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
    expect(recheckMock).not.toHaveBeenCalled();
  });
});

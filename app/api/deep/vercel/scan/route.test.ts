import { describe, it, expect, vi, beforeEach } from "vitest";

const requireProUserMock = vi.fn();
const singleMock = vi.fn();
const runVercelEnvAuditMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/deep/vercelRun", () => ({ runVercelEnvAudit: runVercelEnvAuditMock }));
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
  });

  it("returns 403 when the caller is not Pro", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await POST();
    expect(res.status).toBe(403);
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
  });

  it("returns 400 when Vercel is not connected (no stored token)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: null, vercel_team_id: null } });
    const res = await POST();
    expect(res.status).toBe(400);
    expect(runVercelEnvAuditMock).not.toHaveBeenCalled();
  });

  it("runs the audit and returns counts on success", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: "enc", vercel_team_id: "t1" } });
    runVercelEnvAuditMock.mockResolvedValue({ total: 3, newCount: 1, findings: [] });

    const res = await POST();
    const body = await res.json();

    expect(runVercelEnvAuditMock).toHaveBeenCalledWith("u1", "enc", "t1");
    expect(body).toEqual({ ok: true, total: 3, newCount: 1 });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 502 with a generic message when the audit throws", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { vercel_access_token_encrypted: "enc", vercel_team_id: null } });
    runVercelEnvAuditMock.mockRejectedValue(new Error("Vercel API is down with a very specific internal error"));

    const res = await POST();
    const body = await res.json();
    expect(res.status).toBe(502);
    expect(body.error).toBe("Scan failed. Try again.");
    expect(JSON.stringify(body)).not.toContain("Vercel API is down");
  });
});

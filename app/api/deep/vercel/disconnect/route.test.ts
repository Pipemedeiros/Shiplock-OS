import { describe, it, expect, vi, beforeEach } from "vitest";

const requireProUserMock = vi.fn();
const updateEqMock = vi.fn();
const archiveIsMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "user_profiles") {
        return { update: () => ({ eq: updateEqMock }) };
      }
      if (table === "deep_findings") {
        return { update: () => ({ eq: () => ({ eq: () => ({ is: archiveIsMock }) }) }) };
      }
      throw new Error(`unexpected table ${table}`);
    },
  }),
}));

const { POST } = await import("./route");

describe("POST /api/deep/vercel/disconnect", () => {
  beforeEach(() => {
    requireProUserMock.mockReset();
    updateEqMock.mockReset().mockResolvedValue({ error: null });
    archiveIsMock.mockReset().mockResolvedValue({ error: null });
  });

  it("returns 403 when the caller is not Pro, without touching the DB", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await POST();
    expect(res.status).toBe(403);
    expect(updateEqMock).not.toHaveBeenCalled();
  });

  it("purges all 4 credential columns and archives active findings on success", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    const res = await POST();
    const body = await res.json();

    expect(body).toEqual({ ok: true });
    expect(updateEqMock).toHaveBeenCalledWith("id", "u1");
    expect(archiveIsMock).toHaveBeenCalledWith("archived_at", null);
  });

  it("returns 500 when purging the credential fails, and does not archive findings", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    updateEqMock.mockResolvedValue({ error: { message: "db down" } });
    const res = await POST();
    expect(res.status).toBe(500);
    expect(archiveIsMock).not.toHaveBeenCalled();
  });
});

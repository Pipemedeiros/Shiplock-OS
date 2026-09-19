import { describe, it, expect, vi, beforeEach } from "vitest";

const requireProUserMock = vi.fn();
const updateEqMock = vi.fn();
const archiveIsMock = vi.fn();
const linksDeleteEqMock = vi.fn();
const factsDeleteEqMock = vi.fn();
const deleteScopeMock = vi.fn();
const profileUpdateMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "user_profiles") {
        return { update: (payload: unknown) => { profileUpdateMock(payload); return { eq: updateEqMock }; } };
      }
      if (table === "deep_findings") {
        return { update: () => ({ eq: () => ({ eq: () => ({ is: archiveIsMock }) }) }) };
      }
      if (table === "provider_repository_links") {
        return { delete: () => ({ eq: (column: string, value: unknown) => {
          deleteScopeMock(table, column, value); return { eq: linksDeleteEqMock };
        } }) };
      }
      if (table === "graph_facts") {
        return { delete: () => ({ eq: (column: string, value: unknown) => {
          deleteScopeMock(table, column, value); return { eq: factsDeleteEqMock };
        } }) };
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
    linksDeleteEqMock.mockReset().mockResolvedValue({ error: null });
    factsDeleteEqMock.mockReset().mockResolvedValue({ error: null });
    deleteScopeMock.mockReset();
    profileUpdateMock.mockReset();
  });

  it("returns 403 when the caller is not Pro, without touching the DB", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await POST();
    expect(res.status).toBe(403);
    expect(updateEqMock).not.toHaveBeenCalled();
    expect(deleteScopeMock).not.toHaveBeenCalled();
  });

  it("purges credentials, mappings and runtime facts before archiving findings", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    const res = await POST();
    const body = await res.json();

    expect(body).toEqual({ ok: true });
    expect(updateEqMock).toHaveBeenCalledWith("id", "u1");
    expect(archiveIsMock).toHaveBeenCalledWith("archived_at", null);
    expect(linksDeleteEqMock).toHaveBeenCalledWith("provider", "vercel");
    expect(factsDeleteEqMock).toHaveBeenCalledWith("collector", "runtime");
    expect(deleteScopeMock.mock.calls).toEqual([
      ["provider_repository_links", "user_id", "u1"], ["graph_facts", "user_id", "u1"],
    ]);
    expect(profileUpdateMock).toHaveBeenCalledWith({
      vercel_access_token_encrypted: null, vercel_team_id: null,
      vercel_config_id: null, vercel_connected_at: null,
    });
  });

  it("reports an evidence cleanup failure and does not claim success", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    factsDeleteEqMock.mockResolvedValue({ error: { message: "db down" } });
    const res = await POST();
    expect(res.status).toBe(500);
    expect(archiveIsMock).not.toHaveBeenCalled();
    expect(deleteScopeMock).toHaveBeenCalledTimes(2);
  });

  it("returns 500 when purging the credential fails, and does not archive findings", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    updateEqMock.mockResolvedValue({ error: { message: "db down" } });
    const res = await POST();
    expect(res.status).toBe(500);
    expect(archiveIsMock).not.toHaveBeenCalled();
    expect(deleteScopeMock).not.toHaveBeenCalled();
  });
});

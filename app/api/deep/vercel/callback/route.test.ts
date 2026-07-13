import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const requireProUserMock = vi.fn();
const exchangeCodeForTokenMock = vi.fn();
const encryptMock = vi.fn();
const updateMock = vi.fn();
const eqMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/deep/vercel", () => ({ exchangeCodeForToken: exchangeCodeForTokenMock }));
vi.mock("@/lib/crypto", () => ({ encrypt: encryptMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({ update: (...args: unknown[]) => { updateMock(...args); return { eq: eqMock }; } }),
  }),
}));

const { GET } = await import("./route");

function req(query: string) {
  return new NextRequest(`https://shiplock.dev/api/deep/vercel/callback${query}`);
}

describe("GET /api/deep/vercel/callback", () => {
  beforeEach(() => {
    requireProUserMock.mockReset();
    exchangeCodeForTokenMock.mockReset();
    encryptMock.mockReset().mockReturnValue("encrypted-token");
    updateMock.mockReset();
    eqMock.mockReset().mockResolvedValue({ error: null });
  });

  it("redirects to forbidden when the caller is not Pro, without exchanging the code", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await GET(req("?code=abc"));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=forbidden");
    expect(exchangeCodeForTokenMock).not.toHaveBeenCalled();
  });

  it("redirects to error when no code param is present", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    const res = await GET(req(""));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=error");
    expect(exchangeCodeForTokenMock).not.toHaveBeenCalled();
  });

  it("stores the encrypted token and redirects to the connected default on success", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: "t1", configurationId: "c1" });
    const res = await GET(req("?code=abc"));

    expect(encryptMock).toHaveBeenCalledWith("raw-token");
    expect(updateMock).toHaveBeenCalledWith(expect.objectContaining({
      vercel_access_token_encrypted: "encrypted-token",
      vercel_team_id: "t1",
      vercel_config_id: "c1",
    }));
    expect(eqMock).toHaveBeenCalledWith("id", "u1");
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=connected");
  });

  it("redirects to error when the token exchange throws", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockRejectedValue(new Error("boom"));
    const res = await GET(req("?code=abc"));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=error");
  });

  it("redirects to error when the DB update fails", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    eqMock.mockResolvedValue({ error: { message: "db down" } });
    const res = await GET(req("?code=abc"));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=error");
  });

  it("follows a legitimate vercel.com next param (popup-close flow)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("https://vercel.com/integrations/close");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://vercel.com/integrations/close");
  });

  it("follows a subdomain of vercel.com in next", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("https://my-team.vercel.com/done");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://my-team.vercel.com/done");
  });

  it("follows a same-origin next param", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("https://shiplock.dev/onboarding?step=2");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/onboarding?step=2");
  });

  it("open-redirect guard: rejects an attacker-controlled next param and falls back to the safe default", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("https://evil.com/phish");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=connected");
  });

  it("open-redirect guard: rejects a lookalike domain (vercel.com.evil.com)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("https://vercel.com.evil.com/phish");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=connected");
  });

  it("open-redirect guard: rejects a protocol-relative / javascript-style next value", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    exchangeCodeForTokenMock.mockResolvedValue({ accessToken: "raw-token", teamId: null, configurationId: null });
    const next = encodeURIComponent("javascript:alert(1)");
    const res = await GET(req(`?code=abc&next=${next}`));
    expect(res.headers.get("location")).toBe("https://shiplock.dev/dashboard?vercel=connected");
  });
});

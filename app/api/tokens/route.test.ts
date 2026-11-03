import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const getUser = vi.fn();
const profile = vi.fn();
const insertToken = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser },
    from: (table: string) => {
      if (table === "user_profiles") return { select: () => ({ eq: () => ({ maybeSingle: profile }) }) };
      if (table === "api_tokens") return { insert: insertToken };
      throw new Error(`unexpected table: ${table}`);
    },
  }),
}));

const { POST } = await import("./route");
const jwt = (aal: string) => `h.${Buffer.from(JSON.stringify({ sub: "user-1", aal })).toString("base64url")}.s`;
const request = (token = "session-token") => new NextRequest("https://shiplock.dev/api/tokens", {
  method: "POST",
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  body: JSON.stringify({ name: "Codex" }),
});

describe("MCP token issuance with billing parked", () => {
  beforeEach(() => {
    getUser.mockReset().mockResolvedValue({ data: { user: { id: "user-1" } } });
    profile.mockReset();
    insertToken.mockReset().mockResolvedValue({ error: null });
  });

  it("issues a PAT to a signed-in account with an unpaid profile", async () => {
    profile.mockResolvedValue({ data: { is_paid: false } });
    const response = await POST(request());
    expect(response.status).toBe(200);
    expect((await response.json()).token).toMatch(/^shiplock_pat_/);
    expect(insertToken).toHaveBeenCalledOnce();
  });

  // Two-step sign-in: an MCP token outlives the session, so issuing one to a
  // user with an authenticator needs a session that passed the code.
  it("refuses a token to a user with an authenticator whose session is still aal1", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "user-1", factors: [{ status: "verified" }] } } });
    profile.mockResolvedValue({ data: { is_paid: false } });
    const response = await POST(request(jwt("aal1")));
    expect(response.status).toBe(403);
    expect(insertToken).not.toHaveBeenCalled();
    expect((await POST(request(jwt("aal2")))).status).toBe(200);
  });

  it("refuses an eleventh active token plainly and returns no token", async () => {
    profile.mockResolvedValue({ data: { is_paid: false } });
    insertToken.mockResolvedValue({ error: { message: "token limit reached" } });
    const response = await POST(request());
    expect(response.status).toBe(429);
    const body = await response.json();
    expect(body.token).toBeUndefined();
    expect(body.error).toMatch(/10 active tokens/);
  });

  it("does not issue a PAT when the signed-in account has no profile", async () => {
    profile.mockResolvedValue({ data: null });
    const response = await POST(request());
    expect(response.status).toBe(402);
    expect(insertToken).not.toHaveBeenCalled();
  });
});

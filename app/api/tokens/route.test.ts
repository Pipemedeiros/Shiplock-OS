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
const request = () => new NextRequest("https://shiplock.dev/api/tokens", {
  method: "POST",
  headers: { authorization: "Bearer session-token", "content-type": "application/json" },
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

  it("refuses an eleventh active token plainly and returns no token (3H-2)", async () => {
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

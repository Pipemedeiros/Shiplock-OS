import { beforeEach, describe, expect, it, vi } from "vitest";

const tokenRow = vi.fn();
const profileRow = vi.fn();
const updateStamp = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "api_tokens") return {
        select: () => ({ eq: () => ({ maybeSingle: tokenRow }) }),
        update: updateStamp,
      };
      if (table === "user_profiles") return { select: () => ({ eq: () => ({ maybeSingle: profileRow }) }) };
      throw new Error(`unexpected table: ${table}`);
    },
  }),
}));

const { generateToken, resolveApiToken } = await import("./apiTokens");

describe("PAT resolution uses the central access gate", () => {
  beforeEach(() => {
    tokenRow.mockReset().mockResolvedValue({ data: { id: "pat-1", user_id: "user-1", revoked_at: null } });
    profileRow.mockReset();
    updateStamp.mockReset().mockReturnValue({ eq: () => Promise.resolve({ error: null }) });
  });

  it("allows an unpaid profile while billing is parked", async () => {
    profileRow.mockResolvedValue({ data: { is_paid: false } });
    expect(await resolveApiToken(generateToken().raw)).toEqual({ userId: "user-1", hasAccess: true });
  });

  it("never treats a missing profile as access", async () => {
    profileRow.mockResolvedValue({ data: null });
    expect(await resolveApiToken(generateToken().raw)).toEqual({ userId: "user-1", hasAccess: false });
  });
});

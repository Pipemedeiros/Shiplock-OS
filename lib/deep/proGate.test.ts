import { describe, it, expect, vi, beforeEach } from "vitest";

const getUserMock = vi.fn();
const getClaimsMock = vi.fn();
const singleMock = vi.fn();

vi.mock("@/lib/supabaseServer", () => ({
  getSupabaseServer: vi.fn(async () => ({
    auth: { getUser: getUserMock, getClaims: getClaimsMock },
  })),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          single: singleMock,
        }),
      }),
    }),
  }),
}));

// Imported after the mocks so proGate picks up the mocked modules.
const { requireProUser } = await import("./proGate");

describe("requireProUser", () => {
  beforeEach(() => {
    getUserMock.mockReset();
    singleMock.mockReset();
    getClaimsMock.mockReset().mockResolvedValue({ data: { claims: { aal: "aal1" } }, error: null });
  });

  // Two-step sign-in (lib/mfa.ts): getUser's factor list is the auth
  // server's own answer, and aal comes from the verified token.
  it("refuses a user with a verified authenticator until the session reaches aal2", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com", factors: [{ status: "verified" }] } } });
    singleMock.mockResolvedValue({ data: { is_paid: false } });
    expect(await requireProUser()).toBeNull();
    getClaimsMock.mockResolvedValue({ data: { claims: { aal: "aal2" } }, error: null });
    expect(await requireProUser()).toEqual({ userId: "user-1", email: "a@b.com" });
  });

  it("refuses a user with an authenticator when the token's level cannot be read", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com", factors: [{ status: "verified" }] } } });
    getClaimsMock.mockResolvedValue({ data: null, error: new Error("x") });
    singleMock.mockResolvedValue({ data: { is_paid: false } });
    expect(await requireProUser()).toBeNull();
  });

  it("returns null when there is no session", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    expect(await requireProUser()).toBeNull();
    expect(singleMock).not.toHaveBeenCalled();
  });

  it("admits an unpaid account while billing is parked", async () => {
    // The gate answers "may this account use the product", and with billing
    // parked (lib/access.ts) that is yes for anyone signed in. The half that
    // still matters is below: the answer comes from the database, never the
    // session object.
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com" } } });
    singleMock.mockResolvedValue({ data: { is_paid: false } });
    expect(await requireProUser()).toEqual({ userId: "user-1", email: "a@b.com" });
  });

  it("returns null when the profile row is missing entirely", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com" } } });
    singleMock.mockResolvedValue({ data: null });
    expect(await requireProUser()).toBeNull();
  });

  it("returns the user context when authenticated and paid", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com" } } });
    singleMock.mockResolvedValue({ data: { is_paid: true } });
    expect(await requireProUser()).toEqual({ userId: "user-1", email: "a@b.com" });
  });

  it("never trusts a client-supplied paid flag — always reads DB via service role", async () => {
    // Even if the "session" user object carried an is_paid-looking field, the
    // gate must ignore it. With the profile row absent the answer is no, and a
    // truthy flag on the session cannot conjure the row into existence.
    getUserMock.mockResolvedValue({
      data: { user: { id: "user-1", email: "a@b.com", is_paid: true } },
    });
    singleMock.mockResolvedValue({ data: null });
    expect(await requireProUser()).toBeNull();
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";

const getUserMock = vi.fn();
const singleMock = vi.fn();

vi.mock("@/lib/supabaseServer", () => ({
  getSupabaseServer: vi.fn(async () => ({
    auth: { getUser: getUserMock },
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
  });

  it("returns null when there is no session", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    expect(await requireProUser()).toBeNull();
    expect(singleMock).not.toHaveBeenCalled();
  });

  it("returns null when the session exists but is_paid is false", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1", email: "a@b.com" } } });
    singleMock.mockResolvedValue({ data: { is_paid: false } });
    expect(await requireProUser()).toBeNull();
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
    // Even if the "session" user object somehow carried an is_paid-looking
    // field, requireProUser must ignore it and only trust the admin-client read.
    getUserMock.mockResolvedValue({
      data: { user: { id: "user-1", email: "a@b.com", is_paid: true } },
    });
    singleMock.mockResolvedValue({ data: { is_paid: false } });
    expect(await requireProUser()).toBeNull();
  });
});

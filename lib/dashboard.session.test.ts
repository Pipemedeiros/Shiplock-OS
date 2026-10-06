import { beforeEach, describe, expect, it, vi } from "vitest";

// Speed (Felipe 2026-10-01: "I touch a button, and it takes a little longer").
// The dashboard session must come from the signed access token, verified
// locally against the project's ES256 key, not from a round trip to the auth
// server on every click. PostgREST already trusts the same token for RLS, so
// this is the same boundary, not a weaker one.
const getClaims = vi.fn();
const getUser = vi.fn();
const single = vi.fn();
vi.mock("@/lib/supabaseServer", () => ({
  getSupabaseServer: async () => ({
    auth: { getClaims, getUser },
    from: () => ({ select: () => ({ eq: () => ({ single }) }) }),
  }),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({}) }));
const checkMfa = vi.fn();
vi.mock("@/lib/mfa", () => ({ checkMfa: (...args: unknown[]) => checkMfa(...args) }));
const redirect = vi.fn((to: string) => { throw new Error(`redirect:${to}`); });
vi.mock("next/navigation", () => ({ redirect: (to: string) => redirect(to) }));

beforeEach(() => { vi.clearAllMocks(); checkMfa.mockResolvedValue("ok"); });

describe("requireDashboardSession", () => {
  it("reads the caller from verified token claims, never the auth server", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", email: "f@x.dev", app_metadata: { provider: "github" } } }, error: null });
    single.mockResolvedValue({ data: { is_paid: true } });
    const { requireDashboardSession } = await import("./dashboard");
    await expect(requireDashboardSession()).resolves.toEqual({ userId: "u1", email: "f@x.dev", provider: "github", isPaid: true });
    expect(getUser).not.toHaveBeenCalled();
  });

  it("sends an unverified or expired token to sign in", async () => {
    getClaims.mockResolvedValue({ data: null, error: new Error("invalid JWT") });
    const { requireDashboardSession } = await import("./dashboard");
    await expect(requireDashboardSession()).rejects.toThrow("redirect:/auth");
  });

  // Two-step sign-in: a user with a verified authenticator signed in at aal1
  // (password, magic link or Google) must enter the code before any page.
  it("sends a user with an authenticator to the code step until aal2", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", aal: "aal1" } }, error: null });
    checkMfa.mockResolvedValue("step_up");
    const { requireDashboardSession } = await import("./dashboard");
    await expect(requireDashboardSession()).rejects.toThrow("redirect:/auth/mfa");
    expect(checkMfa).toHaveBeenCalledWith("u1", "aal1");
  });

  it("fails closed when the factors cannot be read", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", aal: "aal1" } }, error: null });
    checkMfa.mockResolvedValue("unknown");
    const { requireDashboardSession } = await import("./dashboard");
    await expect(requireDashboardSession()).rejects.toThrow("redirect:/auth/mfa");
  });

  it("serves a session that already passed the code", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", aal: "aal2" } }, error: null });
    single.mockResolvedValue({ data: { is_paid: false } });
    const { requireDashboardSession } = await import("./dashboard");
    await expect(requireDashboardSession()).resolves.toMatchObject({ userId: "u1" });
    expect(checkMfa).toHaveBeenCalledWith("u1", "aal2");
  });
});

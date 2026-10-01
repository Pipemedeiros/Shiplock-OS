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
const redirect = vi.fn((to: string) => { throw new Error(`redirect:${to}`); });
vi.mock("next/navigation", () => ({ redirect: (to: string) => redirect(to) }));

beforeEach(() => { vi.clearAllMocks(); });

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
});

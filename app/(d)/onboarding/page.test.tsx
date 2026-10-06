import { beforeEach, describe, expect, it, vi } from "vitest";

// Two-step sign-in (lib/mfa.ts): onboarding lists the installation's private
// repositories, so a user with a verified authenticator signed in at aal1
// enters the code first, like every dashboard page.
const getUser = vi.fn();
const getClaims = vi.fn();
const adminFrom = vi.fn();
vi.mock("@/lib/supabaseServer", () => ({ getSupabaseServer: async () => ({ auth: { getUser, getClaims } }) }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: adminFrom }) }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: vi.fn(), listRepos: vi.fn() }));
vi.mock("@/components/v3/OnboardingFlow", () => ({ OnboardingFlow: () => null }));
vi.mock("next/navigation", () => ({ redirect: (to: string) => { throw new Error(`redirect:${to}`); } }));
const { default: Onboarding } = await import("./page");

const profile = { select: () => ({ eq: () => ({ single: async () => ({ data: { github_installation_id: null } }) }) }) };
const verified = [{ status: "verified" }];

describe("onboarding page", () => {
  beforeEach(() => { vi.clearAllMocks(); adminFrom.mockReturnValue(profile); });

  it("sends a user with an authenticator to the code step before reading anything", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u1", factors: verified } } });
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", aal: "aal1" } }, error: null });
    await expect(Onboarding()).rejects.toThrow("redirect:/auth/mfa?next=/onboarding");
    expect(adminFrom).not.toHaveBeenCalled();
  });

  it("fails closed to the code step when the level cannot be read", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u1", factors: verified } } });
    getClaims.mockResolvedValue({ data: null, error: new Error("unreadable") });
    await expect(Onboarding()).rejects.toThrow("redirect:/auth/mfa?next=/onboarding");
  });

  it("serves a session that passed the code, and a user without an authenticator", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u1", factors: verified } } });
    getClaims.mockResolvedValue({ data: { claims: { sub: "u1", aal: "aal2" } }, error: null });
    await expect(Onboarding()).resolves.toBeTruthy();
    getUser.mockResolvedValue({ data: { user: { id: "u2", factors: [] } } });
    getClaims.mockResolvedValue({ data: { claims: { sub: "u2", aal: "aal1" } }, error: null });
    await expect(Onboarding()).resolves.toBeTruthy();
  });
});

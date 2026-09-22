import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), rpc: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));
vi.mock("@/lib/env", () => ({ env: {
  NEXT_PUBLIC_APP_URL: "https://shiplock.test",
  GITHUB_APP_SLUG: "shiplock-test",
} }));
vi.mock("@/lib/githubInstallState", () => ({
  GITHUB_INSTALL_COOKIE: "shiplock_github_install",
  GITHUB_INSTALL_TTL_SECONDS: 600,
  newGithubInstallNonce: () => "nonce-value",
  hashGithubInstallNonce: () => "a".repeat(64),
}));

import { GET } from "./route";

describe("GET /api/deep/github/connect", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.user.mockResolvedValue({ userId: "11111111-1111-4111-8111-111111111111", email: null });
    mocks.rpc.mockResolvedValue({ data: true, error: null });
  });

  it("records a one-time tenant handshake before leaving for GitHub", async () => {
    const response = await GET();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://github.com/apps/shiplock-test/installations/new");
    expect(response.headers.get("set-cookie")).toContain("shiplock_github_install=nonce-value");
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("SameSite=lax");
    expect(mocks.rpc).toHaveBeenCalledWith("begin_github_install", {
      p_user: "11111111-1111-4111-8111-111111111111",
      p_nonce_hash: "a".repeat(64),
    });
  });

  it("never redirects to GitHub when the handshake was not stored", async () => {
    mocks.rpc.mockResolvedValue({ data: false, error: null });
    const response = await GET();
    expect(response.headers.get("location")).toBe("https://shiplock.test/onboarding?github=error");
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("requires a signed-in product user before creating state", async () => {
    mocks.user.mockResolvedValue(null);
    const response = await GET();
    expect(response.headers.get("location")).toBe("https://shiplock.test/dashboard?github=forbidden");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
});

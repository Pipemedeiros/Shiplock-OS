import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const mocks = vi.hoisted(() => ({
  user: vi.fn(), access: vi.fn(), missing: vi.fn(), rpc: vi.fn(),
}));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationAccess: mocks.access,
  missingInstallationPermissions: mocks.missing,
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));
vi.mock("@/lib/githubInstallState", () => ({
  GITHUB_INSTALL_COOKIE: "shiplock_github_install",
  hashGithubInstallNonce: () => "b".repeat(64),
}));

import { GET } from "./route";

const request = (installation = "42", cookie = "nonce-value") => new NextRequest(
  `https://shiplock.test/api/deep/github/callback?installation_id=${installation}`,
  { headers: cookie ? { cookie: `shiplock_github_install=${cookie}` } : undefined },
);

describe("GET /api/deep/github/callback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("NEXT_PUBLIC_APP_URL", "https://shiplock.test");
    mocks.user.mockResolvedValue({ userId: "11111111-1111-4111-8111-111111111111", email: null });
    mocks.access.mockResolvedValue({ token: "ephemeral", permissions: {} });
    mocks.missing.mockReturnValue([]);
    mocks.rpc.mockResolvedValue({ data: true, error: null });
  });

  it("verifies permissions and consumes the exact handshake before binding", async () => {
    const response = await GET(request());
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://shiplock.test/onboarding?github=connected");
    expect(response.headers.get("set-cookie")).toContain("shiplock_github_install=;");
    expect(mocks.access).toHaveBeenCalledWith("42");
    expect(mocks.rpc).toHaveBeenCalledWith("complete_github_install", {
      p_user: "11111111-1111-4111-8111-111111111111",
      p_nonce_hash: "b".repeat(64),
      p_installation: "42",
    });
  });

  it("refuses a missing, malformed, or replayed handshake", async () => {
    expect((await GET(request("42", ""))).headers.get("location")).toContain("github=error");
    expect((await GET(request("not-a-number"))).headers.get("location")).toContain("github=error");
    expect(mocks.access).not.toHaveBeenCalled();

    mocks.rpc.mockResolvedValue({ data: false, error: null });
    expect((await GET(request())).headers.get("location")).toContain("github=error");
  });

  it("does not bind an installation with weaker permissions than the UI promises", async () => {
    mocks.missing.mockReturnValue(["checks"]);
    const response = await GET(request());
    expect(response.headers.get("location")).toBe("https://shiplock.test/onboarding?github=permissions");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
});

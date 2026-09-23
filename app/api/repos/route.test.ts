import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  user: vi.fn(),
  token: vi.fn(),
  repos: vi.fn(),
  profile: vi.fn(),
  rpc: vi.fn(),
}));

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: mocks.token,
  listRepos: mocks.repos,
}));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table !== "user_profiles") throw new Error(`unexpected table ${table}`);
      return {
        select: () => ({
          eq: () => ({ single: mocks.profile }),
        }),
      };
    },
    rpc: mocks.rpc,
  }),
}));

import { POST } from "./route";

const request = (repositories: unknown) => new Request("https://shiplock.dev/api/repos", {
  method: "POST",
  headers: { "content-type": "application/json", origin: "https://shiplock.dev" },
  body: JSON.stringify({ repositories }),
});

describe("POST /api/repos", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.user.mockResolvedValue({ userId: "11111111-1111-4111-8111-111111111111", email: null });
    mocks.profile.mockResolvedValue({ data: { github_installation_id: 42 }, error: null });
    mocks.token.mockResolvedValue("installation-token");
    mocks.repos.mockResolvedValue([
      { id: "9001", fullName: "acme/app", defaultBranch: "develop", isPrivate: false, visibility: "public" },
      { id: "9002", fullName: "acme/api", defaultBranch: "main", isPrivate: true, visibility: "private" },
    ]);
    mocks.rpc.mockResolvedValue({
      data: [{ id: "22222222-2222-4222-8222-222222222222", full_name: "acme/app" }],
      error: null,
    });
  });

  it("requires an authenticated product user", async () => {
    mocks.user.mockResolvedValue(null);
    const response = await POST(request(["acme/app"]));
    expect(response.status).toBe(401);
    expect(mocks.token).not.toHaveBeenCalled();
  });

  it("refuses repository names the current installation cannot see", async () => {
    const response = await POST(request(["other/private"]));
    expect(response.status).toBe(409);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("atomically persists only live GitHub metadata", async () => {
    const response = await POST(request(["acme/app"]));
    expect(response.status).toBe(200);
    expect(mocks.rpc).toHaveBeenCalledWith("replace_selected_repositories", {
      p_user: "11111111-1111-4111-8111-111111111111",
      p_repositories: [{
        full_name: "acme/app",
        github_repo_id: "9001",
        default_branch: "develop",
        private: false,
      }],
    });
  });

  it("does not partially change selection when GitHub or storage fails", async () => {
    mocks.repos.mockRejectedValueOnce(new Error("GitHub unavailable"));
    expect((await POST(request(["acme/app"]))).status).toBe(503);
    expect(mocks.rpc).not.toHaveBeenCalled();

    mocks.repos.mockResolvedValueOnce([
      { id: "9001", fullName: "acme/app", defaultBranch: "main", isPrivate: true, visibility: "private" },
    ]);
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "database unavailable" } });
    expect((await POST(request(["acme/app"]))).status).toBe(503);
  });

  it("uses the same atomic operation to deselect every repository", async () => {
    mocks.rpc.mockResolvedValue({ data: [], error: null });
    const response = await POST(request([]));
    expect(response.status).toBe(200);
    expect(mocks.rpc).toHaveBeenCalledWith("replace_selected_repositories", {
      p_user: "11111111-1111-4111-8111-111111111111",
      p_repositories: [],
    });
  });
});

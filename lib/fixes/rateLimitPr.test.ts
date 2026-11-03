import { beforeEach, describe, expect, it, vi } from "vitest";

// One click opens one PR that adds only the off-by-default helper, on
// a new branch from the default branch; never the default branch itself.
const gh = vi.hoisted(() => ({ token: vi.fn(), tree: vi.fn(), branchSha: vi.fn(), createBranch: vi.fn(), putFile: vi.fn(),
  openPr: vi.fn(), findPr: vi.fn(), fileSha: vi.fn() }));
const rows = vi.hoisted(() => ({ repositories: null as unknown, user_profiles: null as unknown, traffic_route_observations: [] as unknown }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: gh.token, listTree: gh.tree, getBranchSha: gh.branchSha,
  createBranch: gh.createBranch, putFile: gh.putFile, openPullRequest: gh.openPr, findOpenPullRequestForBranch: gh.findPr, getFileSha: gh.fileSha }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof rows) => {
  const q: Record<string, unknown> = {};
  const result = () => Promise.resolve({ data: rows[table], error: null });
  Object.assign(q, { select: () => q, eq: () => q, order: () => q, limit: () => q, maybeSingle: result,
    then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => result().then(res, rej) });
  return q;
} }) }));

import { openRateLimitPr } from "./rateLimitPr";

const finding = "traffic:app/api/orders/[id]/route.ts";
beforeEach(() => {
  vi.clearAllMocks();
  rows.repositories = { full_name: "acme/app", default_branch: "main", selected: true };
  rows.user_profiles = { github_installation_id: 42 };
  rows.traffic_route_observations = [{ path: "/api/orders/1", suspicious_requests: 30 }, { path: "/api/orders/2", suspicious_requests: 20 }];
  gh.token.mockResolvedValue("tok");
  gh.tree.mockResolvedValue([{ path: "app/api/orders/[id]/route.ts", type: "blob" }, { path: "package.json", type: "blob" }]);
  gh.findPr.mockResolvedValue(null);
  gh.branchSha.mockImplementation(async (_t: string, _r: string, branch: string) => { if (branch === "main") return "a".repeat(40); throw new Error("404"); });
  gh.openPr.mockResolvedValue("https://github.com/acme/app/pull/12");
});

describe("openRateLimitPr", () => {
  it("adds the helper on a new branch and opens one PR against the default branch", async () => {
    expect(await openRateLimitPr("u1", finding, "r1")).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/12", number: 12 });
    const branch = gh.createBranch.mock.calls[0][2];
    expect(branch).toMatch(/^shiplock\/rate-limit-[0-9a-f]{20}$/);
    expect(gh.putFile).toHaveBeenCalledTimes(1);
    expect(gh.putFile.mock.calls[0].slice(1, 4)).toEqual(["acme/app", "lib/shiplock-rate-limit.ts", branch]);
    const [, , head, base, title, body] = gh.openPr.mock.calls[0];
    expect([head, base]).toEqual([branch, "main"]);
    expect(title).toBe("Rate limit /api/orders/:id (suggested by ShipLock)");
    expect(body).toContain("50 suspicious requests");
    for (const call of gh.putFile.mock.calls) expect(call[3]).not.toBe("main");
  });
  it("on a retry, does not re-create a helper already on the branch", async () => {
    gh.branchSha.mockResolvedValue("a".repeat(40));
    gh.fileSha.mockResolvedValue("b".repeat(40));
    expect(await openRateLimitPr("u1", finding, "r1")).toMatchObject({ status: "opened" });
    expect(gh.createBranch).not.toHaveBeenCalled();
    expect(gh.putFile).not.toHaveBeenCalled();
  });
  it("recovers an already opened PR instead of opening a second one", async () => {
    gh.findPr.mockResolvedValue("https://github.com/acme/app/pull/9");
    expect(await openRateLimitPr("u1", finding, "r1")).toMatchObject({ status: "opened", number: 9 });
    expect(gh.putFile).not.toHaveBeenCalled();
  });
  it.each([
    ["finding_unavailable", () => { rows.traffic_route_observations = [{ path: "/other", suspicious_requests: 5 }]; }],
    ["finding_unavailable", () => { gh.tree.mockResolvedValue([{ path: "package.json", type: "blob" }]); }],
    ["no_changes", () => { gh.tree.mockResolvedValue([{ path: "app/api/orders/[id]/route.ts", type: "blob" }, { path: "lib/shiplock-rate-limit.ts", type: "blob" }]); }],
    ["repository_unavailable", () => { rows.repositories = { full_name: "acme/app", default_branch: "main", selected: false }; }],
    ["repository_unavailable", () => { rows.user_profiles = { github_installation_id: null }; }],
  ])("fails %s without writing", async (code, arrange) => {
    arrange();
    expect(await openRateLimitPr("u1", finding, "r1")).toEqual({ status: "failed", code });
    expect(gh.createBranch).not.toHaveBeenCalled();
    expect(gh.putFile).not.toHaveBeenCalled();
  });
  it("refuses a malformed finding id", async () => {
    expect(await openRateLimitPr("u1", "app/api/orders/route.ts", "r1")).toEqual({ status: "failed", code: "finding_unavailable" });
  });
});

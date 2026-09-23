import { beforeEach, describe, expect, it, vi } from "vitest";

// 8B-3: fix before merge. The fix PR targets the checked PR's own head branch.
const mocks = vi.hoisted(() => ({
  review: vi.fn(), profile: vi.fn(),
  github: { getInstallationToken: vi.fn(), getBranchSha: vi.fn(), createBranch: vi.fn(), putFile: vi.fn(), openPullRequest: vi.fn(), findOpenPullRequestForBranch: vi.fn() },
}));
vi.mock("@/lib/deep/github", () => mocks.github);
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const chain = { select: () => chain, eq: () => chain, maybeSingle: table === "user_profiles" ? mocks.profile : mocks.review };
  return chain;
} }) }));

import { openPullRequestFixPr, pullRequestFixDocument } from "./pullRequestFixPr";

const finding = { id: "diff:unscoped:/api/orders:orders", severity: "CRITICAL", title: "/api/orders reads orders without narrowing it to the caller", detail: "A signed-in user can read another user's row.", file: "app/api/orders/route.ts", evidence: "5 of the 6 routes touching orders filter by owner." };
const review = { pull_request_number: 9, head_ref: "feature/orders", same_repository: true, findings: [finding], repositories: { full_name: "acme/app" } };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.review.mockResolvedValue({ data: review });
  mocks.profile.mockResolvedValue({ data: { github_installation_id: 42 } });
  mocks.github.getInstallationToken.mockResolvedValue("token");
  mocks.github.findOpenPullRequestForBranch.mockResolvedValue(null);
  mocks.github.getBranchSha.mockImplementation(async (_t: string, _r: string, branch: string) => {
    if (branch === "feature/orders") return "head-sha";
    throw new Error("missing");
  });
  mocks.github.openPullRequest.mockResolvedValue("https://github.com/acme/app/pull/10");
});

describe("openPullRequestFixPr", () => {
  it("opens a fix PR from the PR's head into that head branch", async () => {
    expect(await openPullRequestFixPr("u", "review-1", finding.id, "repo-1")).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/10", number: 10 });
    const [, repo, branch, sha] = mocks.github.createBranch.mock.calls[0];
    expect([repo, sha]).toEqual(["acme/app", "head-sha"]);
    expect(branch).toMatch(/^shiplock\/pr-9-fix-[a-f0-9]{12}$/);
    const [, , head, base, title] = mocks.github.openPullRequest.mock.calls[0];
    expect([head, base]).toEqual([branch, "feature/orders"]);
    expect(title).toMatch(/^ShipLock fix request for #9:/);
  });

  it("recovers the PR a previous attempt already opened", async () => {
    mocks.github.findOpenPullRequestForBranch.mockResolvedValue("https://github.com/acme/app/pull/11");
    expect(await openPullRequestFixPr("u", "review-1", finding.id, "repo-1")).toMatchObject({ number: 11 });
    expect(mocks.github.createBranch).not.toHaveBeenCalled();
  });

  it.each([
    ["a fork", () => mocks.review.mockResolvedValue({ data: { ...review, same_repository: false } }), "fork_pull_request"],
    ["a merged or deleted branch", () => mocks.github.getBranchSha.mockRejectedValue(new Error("404")), "pull_request_closed"],
    ["a finding not in this review", () => mocks.review.mockResolvedValue({ data: { ...review, findings: [] } }), "finding_unavailable"],
    ["a missing review", () => mocks.review.mockResolvedValue({ data: null }), "finding_unavailable"],
  ])("never falls back to the default branch for %s", async (_name, arrange, code) => {
    arrange();
    expect(await openPullRequestFixPr("u", "review-1", finding.id, "repo-1")).toEqual({ status: "failed", code });
    expect(mocks.github.openPullRequest).not.toHaveBeenCalled();
  });
});

describe("pullRequestFixDocument", () => {
  it("is labeled a fix request and carries the evidence, never claiming a tested fix", () => {
    const doc = pullRequestFixDocument(9, finding);
    expect(doc).toContain("fix request");
    expect(doc).toContain(finding.evidence);
    expect(doc).toContain(finding.file);
    expect(doc).toMatch(/owner|caller/i);
    expect(doc).not.toMatch(/[—–]/);
  });
});

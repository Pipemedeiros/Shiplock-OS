import { beforeEach, describe, expect, it, vi } from "vitest";

// 3F-C2d-2: the PR builders re-resolve everything server-side and separate
// permanent refusals from retryable GitHub failures.
const mocks = vi.hoisted(() => ({
  open: vi.fn(), fix: vi.fn(), runFixPr: vi.fn(), profile: vi.fn(), repo: vi.fn(), update: vi.fn(),
  github: { createBranch: vi.fn(), findOpenPullRequestForBranch: vi.fn(), getBranchSha: vi.fn(), getInstallationToken: vi.fn(), openPullRequest: vi.fn(), putFile: vi.fn() },
}));
vi.mock("@/lib/agent/dashboardData", () => ({ getOpenFindings: mocks.open }));
vi.mock("./findings", () => ({ getFixFindings: mocks.fix }));
vi.mock("./prRun", () => ({ runFixPr: mocks.runFixPr }));
vi.mock("@/lib/deep/github", () => mocks.github);
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const chain = { eq: () => chain, single: mocks.profile, maybeSingle: mocks.repo };
  return { select: () => chain, update: (payload: unknown) => { mocks.update(table, payload); return { eq: async () => ({ error: null }) }; } };
} }) }));

import { openRiskFixPr } from "./riskFixPr";
import { openFindingFixPr } from "./findingFixPr";

const risk = { rowId: "row-1", id: "agent:idor", title: "IDOR", repository: "acme/app", fixKind: "doc", fixPrUrl: null, claims: [] };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.open.mockResolvedValue([risk]);
  mocks.fix.mockResolvedValue([{ id: "scan:open-table", title: "Open table" }]);
  mocks.profile.mockResolvedValue({ data: { github_installation_id: 42 } });
  mocks.repo.mockResolvedValue({ data: { id: "repo-1", full_name: "acme/app", default_branch: "main" } });
  mocks.github.getInstallationToken.mockResolvedValue("token");
  mocks.github.findOpenPullRequestForBranch.mockResolvedValue(null);
  mocks.github.getBranchSha.mockResolvedValue("sha");
  mocks.github.openPullRequest.mockResolvedValue("https://github.com/acme/app/pull/12");
});

describe("openRiskFixPr", () => {
  it("opens one PR from the stored finding and remembers it on the finding", async () => {
    expect(await openRiskFixPr("u", "agent:idor", "repo-1")).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/12", number: 12 });
    expect(mocks.update).toHaveBeenCalledWith("deep_findings", { fix_pr_url: "https://github.com/acme/app/pull/12", fix_pr_number: 12 });
  });

  it("recovers the PR a previous uncertain attempt already opened", async () => {
    mocks.github.findOpenPullRequestForBranch.mockResolvedValue("https://github.com/acme/app/pull/11");
    expect(await openRiskFixPr("u", "agent:idor", "repo-1")).toMatchObject({ status: "opened", number: 11 });
    expect(mocks.github.openPullRequest).not.toHaveBeenCalled();
  });

  it.each([
    ["an unknown finding", () => mocks.open.mockResolvedValue([]), "finding_unavailable"],
    ["an architecture decision", () => mocks.open.mockResolvedValue([{ ...risk, fixKind: "manual" }]), "not_fixable"],
    ["a different receipt repository", () => mocks.repo.mockResolvedValue({ data: { full_name: "acme/other", default_branch: "main" } }), "repository_unavailable"],
    ["an unselected repository", () => mocks.repo.mockResolvedValue({ data: null }), "repository_unavailable"],
  ])("refuses %s without touching GitHub", async (_name, arrange, code) => {
    arrange();
    expect(await openRiskFixPr("u", "agent:idor", "repo-1")).toEqual({ status: "failed", code });
    expect(mocks.github.openPullRequest).not.toHaveBeenCalled();
  });
});

describe("openFindingFixPr", () => {
  it("passes the customer's edit and returns the opened PR", async () => {
    mocks.runFixPr.mockResolvedValue({ url: "https://github.com/acme/app/pull/13" });
    expect(await openFindingFixPr("u", "scan:open-table", "-- reviewed", "repo-1")).toMatchObject({ status: "opened", number: 13 });
    expect(mocks.runFixPr).toHaveBeenCalledWith("u", expect.objectContaining({ id: "scan:open-table" }), "-- reviewed");
  });

  it.each([
    ["This fix isn't applied through this route.", "not_fixable"],
    ["The finding repository is not selected.", "repository_unavailable"],
  ])("maps a permanent refusal (%s) to failed", async (message, code) => {
    mocks.runFixPr.mockRejectedValue(new Error(message));
    expect(await openFindingFixPr("u", "scan:open-table", null, "repo-1")).toEqual({ status: "failed", code });
  });

  it("rethrows an ambiguous GitHub failure so the receipt becomes uncertain", async () => {
    mocks.runFixPr.mockRejectedValue(new Error("GitHub 502"));
    await expect(openFindingFixPr("u", "scan:open-table", null, "repo-1")).rejects.toThrow("GitHub 502");
  });
});

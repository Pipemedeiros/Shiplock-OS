import { beforeEach, expect, it, vi } from "vitest";

// One click opens at most one dependency-bump PR, for the one
// selected repository named on the receipt.
const state = vi.hoisted(() => ({ profile: vi.fn(), repo: vi.fn(), file: vi.fn(), osv: vi.fn(), open: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const chain = { eq: () => chain, maybeSingle: table === "user_profiles" ? state.profile : state.repo };
  return { select: () => chain };
} }) }));
vi.mock("./github", () => ({
  getInstallationToken: vi.fn(async () => "token"), getFile: state.file, queryOsv: state.osv,
  getBranchSha: vi.fn(async (_t: string, _r: string, branch: string) => { if (branch === "main") return "base"; throw new Error("missing"); }),
  createBranch: vi.fn(async () => {}), getFileSha: vi.fn(async () => "blob"), putFile: vi.fn(async () => {}),
  findOpenPullRequestForBranch: vi.fn(async () => null), openPullRequest: state.open,
}));
import { openDependencyBumpPr } from "./githubFixRun";

beforeEach(() => {
  vi.clearAllMocks();
  state.profile.mockResolvedValue({ data: { github_installation_id: 42 } });
  state.repo.mockResolvedValue({ data: { full_name: "acme/selected", default_branch: "main" } });
  state.file.mockImplementation(async (_t: string, repo: string, path: string) => path === "package.json" ? JSON.stringify({ dependencies: { pkg: "1.0.0" }, name: repo }) : null);
  state.osv.mockResolvedValue([{ dep: { name: "pkg", version: "1.0.0" }, vulns: [{ id: "V", fixedVersion: "1.0.1" }] }]);
  state.open.mockResolvedValue("https://github.com/acme/selected/pull/1");
});

it("opens one bump PR in the receipt's selected repository", async () => {
  expect(await openDependencyBumpPr("user", "repo-1")).toEqual({ status: "opened", url: "https://github.com/acme/selected/pull/1", number: 1 });
  expect(state.open).toHaveBeenCalledTimes(1);
  expect(state.open.mock.calls[0][1]).toBe("acme/selected");
});

it("refuses an unselected repository without touching GitHub", async () => {
  state.repo.mockResolvedValue({ data: null });
  expect(await openDependencyBumpPr("user", "repo-1")).toEqual({ status: "failed", code: "repository_unavailable" });
  expect(state.file).not.toHaveBeenCalled();
});

it("reports no_changes when nothing has a known patched version", async () => {
  state.osv.mockResolvedValue([]);
  expect(await openDependencyBumpPr("user", "repo-1")).toEqual({ status: "failed", code: "no_changes" });
  expect(state.open).not.toHaveBeenCalled();
});

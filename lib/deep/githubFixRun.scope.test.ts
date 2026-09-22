import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ selected: vi.fn(), repos: vi.fn(), file: vi.fn(), osv: vi.fn(), open: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => ({ select: () => ({ eq: () => ({ eq: () => ({ limit: state.selected }) }) }) }) }) }));
vi.mock("./github", () => ({
  getInstallationToken: vi.fn(async () => "token"), listRepos: state.repos, getFile: state.file, queryOsv: state.osv,
  getBranchSha: vi.fn(async (_t:string,_r:string,branch:string) => { if (branch === "main") return "base"; throw new Error("missing"); }),
  createBranch: vi.fn(async () => {}), getFileSha: vi.fn(async () => "blob"), putFile: vi.fn(async () => {}),
  findOpenPullRequestForBranch: vi.fn(async () => null), openPullRequest: state.open,
}));
import { runGithubFix } from "./githubFixRun";

beforeEach(() => {
  vi.clearAllMocks();
  state.selected.mockResolvedValue({data:[{full_name:"acme/selected"}],error:null});
  state.repos.mockResolvedValue([{fullName:"acme/unselected",defaultBranch:"main"},{fullName:"acme/selected",defaultBranch:"main"}]);
  state.file.mockImplementation(async (_t:string,repo:string,path:string) => path === "package.json" ? JSON.stringify({dependencies:{pkg:"1.0.0"},name:repo}) : null);
  state.osv.mockResolvedValue([{dep:{name:"pkg",version:"1.0.0"},vulns:[{id:"V",fixedVersion:"1.0.1"}]}]);
  state.open.mockResolvedValue("https://github.com/acme/selected/pull/1");
});

it("opens dependency fixes only for customer-selected repositories", async () => {
  const result = await runGithubFix("user",42);
  expect(result.repos).toBe(1);
  expect(state.file.mock.calls.some((call) => call[1] === "acme/unselected")).toBe(false);
  expect(state.open.mock.calls[0][1]).toBe("acme/selected");
});

import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ profile: vi.fn(), selected: vi.fn(), token: vi.fn(), repos: vi.fn(), branch: vi.fn(), put: vi.fn(), open: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  from: (table: string) => ({ select: () => {
    if (table === "user_profiles") return { eq: () => ({ maybeSingle: state.profile }) };
    if (table === "repositories") return { eq: () => ({ eq: () => state.selected() }) };
    throw new Error(`unexpected table ${table}`);
  } }),
}) }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: state.token, listRepos: state.repos,
  getBranchSha: vi.fn(async (_token:string,_repo:string,branch:string) => { if (branch === "develop" || branch === "main") return "base"; throw new Error("missing"); }), createBranch: state.branch, putFile: state.put, openPullRequest: state.open,
  findOpenPullRequestForBranch: vi.fn(async () => null), getFile: vi.fn(), getFileSha: vi.fn(async () => null), listTree: vi.fn(),
}));

import { runFixPr } from "./prRun";

const finding = {id:"acme/app::github:secret:key:file.ts",source:"github" as const,title:"Remove key",severity:"CRITICAL" as const,fix:"remove it"};

beforeEach(() => {
  vi.clearAllMocks();
  state.profile.mockResolvedValue({data:{github_installation_id:42},error:null});
  state.selected.mockResolvedValue({data:[{full_name:"acme/app"}],error:null});
  state.token.mockResolvedValue("token");
  state.repos.mockResolvedValue([
    {fullName:"other/repo",defaultBranch:"main"}, {fullName:"acme/app",defaultBranch:"develop"},
  ]);
  state.branch.mockResolvedValue(undefined); state.put.mockResolvedValue(undefined);
  state.open.mockResolvedValue("https://github.com/acme/app/pull/1");
});

it("targets the finding's exact selected repository, never GitHub's first repository", async () => {
  const result = await runFixPr("user",finding,"reviewed content");
  expect(result.url).toContain("acme/app");
  expect(state.branch.mock.calls[0][1]).toBe("acme/app");
  expect(state.open.mock.calls[0][1]).toBe("acme/app");
  expect(state.open.mock.calls[0][3]).toBe("develop");
});

it("refuses a repository named by a finding when the customer did not select it", async () => {
  state.selected.mockResolvedValue({data:[{full_name:"other/repo"}],error:null});
  await expect(runFixPr("user",finding,"reviewed content")).rejects.toThrow("not selected");
  expect(state.branch).not.toHaveBeenCalled();
});

it("refuses an unscoped finding when multiple repositories are selected", async () => {
  state.selected.mockResolvedValue({data:[{full_name:"acme/app"},{full_name:"other/repo"}],error:null});
  await expect(runFixPr("user",{...finding,id:"path:unscoped"},"reviewed content")).rejects.toThrow("Choose the repository");
  expect(state.branch).not.toHaveBeenCalled();
});

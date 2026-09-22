import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  repo: vi.fn(), token: vi.fn(), files: vi.fn(), archive: vi.fn(), post: vi.fn(), scan: vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => ({ select: () => ({
  eq: () => ({ eq: () => ({ eq: () => ({ maybeSingle: state.repo }) }) }),
}) }) }) }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: state.token, listPullRequestFiles: state.files, createCheckRun: state.post,
}));
vi.mock("@/lib/deep/repoArchive", () => ({ fetchRepoArchive: state.archive }));
vi.mock("./stack", () => ({ detectStack: () => ({ framework:"Next.js",language:"TypeScript",router:"App Router",database:[],auth:[],hosting:[],payments:[],services:[],evidence:[] }) }));
vi.mock("./diffScan", () => ({
  scanDiff: state.scan,
  checkSummary: () => ({title:"1 file checked, nothing found",summary:"No deterministic finding."}),
}));

import { runPullRequestCheck } from "./prCheck";

beforeEach(() => {
  vi.clearAllMocks();
  state.repo.mockResolvedValue({data:{id:"repo"},error:null});
  state.token.mockResolvedValue("token");
  state.files.mockResolvedValue({files:[{path:"app/a.ts",content:"ok"}],listed:1,complete:true,coverage:"All 1 changed file was readable."});
  state.archive.mockResolvedValue({files:[{path:"app/a.ts",content:"old"},{path:"lib/auth.ts",content:"auth"}]});
  state.scan.mockReturnValue({verdict:"pass",findings:[],filesChanged:1,routesChanged:0,trivial:false});
  state.post.mockResolvedValue(undefined);
});

it("posts a stable retry identity and a green result only for complete coverage", async () => {
  await runPullRequestCheck({userId:"u",installationId:42,fullName:"acme/app",prNumber:7,headSha:"A".repeat(40)});
  expect(state.post).toHaveBeenCalledWith("token","acme/app","A".repeat(40),"success","1 file checked, nothing found",expect.stringContaining("Repository baseline was readable"),`shiplock:pr:acme/app:7:${"a".repeat(40)}`);
});

it("posts neutral rather than green when any diff or baseline evidence is partial", async () => {
  state.files.mockResolvedValue({files:[],listed:1,complete:false,coverage:"Partial diff: 1 file could not be read."});
  state.archive.mockResolvedValue(null);
  await runPullRequestCheck({userId:"u",installationId:42,fullName:"acme/app",prNumber:7,headSha:"a".repeat(40)});
  expect(state.post).toHaveBeenCalledWith("token","acme/app","a".repeat(40),"neutral",expect.stringMatching(/^Partial review/),expect.stringContaining("cross-file route context is incomplete"),expect.any(String));
});

it("retains a deterministic block even when broader coverage is partial", async () => {
  state.files.mockResolvedValue({files:[{path:".env",content:"secret"}],listed:2,complete:false,coverage:"Partial diff."});
  state.scan.mockReturnValue({verdict:"block",findings:[{id:"secret",severity:"CRITICAL"}],filesChanged:1,routesChanged:0,trivial:false});
  await runPullRequestCheck({userId:"u",installationId:42,fullName:"acme/app",prNumber:7,headSha:"a".repeat(40)});
  expect(state.post.mock.calls[0][3]).toBe("failure");
});

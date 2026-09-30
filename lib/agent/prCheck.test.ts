import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  repo: vi.fn(), routes: vi.fn(), token: vi.fn(), files: vi.fn(), archive: vi.fn(), post: vi.fn(), scan: vi.fn(), pr: vi.fn(), persist: vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => ({ select: () => ({
  eq: () => ({ eq: () => ({ eq: () => ({ maybeSingle: state.repo }) }) }),
}) }) }) }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: state.token, listPullRequestFiles: state.files, createCheckRun: state.post, getPullRequest: state.pr,
}));
vi.mock("@/lib/deep/repoArchive", () => ({ fetchRepoArchive: state.archive }));
vi.mock("@/lib/graph/routeInventory", () => ({ collectRoutes: state.routes }));
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
  state.pr.mockResolvedValue({ headRef: "feature/orders", headRepository: "acme/app", sameRepository: true, title: "Add orders", url: "https://github.com/acme/app/pull/7" });
  state.persist.mockResolvedValue(undefined);
  state.routes.mockReturnValue([]);
});
const check = (headSha: string) => runPullRequestCheck({userId:"u",installationId:42,fullName:"acme/app",prNumber:7,headSha,persistReview:state.persist});

it("posts a stable retry identity and a green result only for complete coverage", async () => {
  await check("A".repeat(40));
  expect(state.post).toHaveBeenCalledWith("token","acme/app","A".repeat(40),"success","1 file checked, nothing found",expect.stringContaining("Repository baseline was readable"),`shiplock:pr:acme/app:7:${"a".repeat(40)}`);
});

it("posts neutral rather than green when any diff or baseline evidence is partial", async () => {
  state.files.mockResolvedValue({files:[],listed:1,complete:false,coverage:"Partial diff: 1 file could not be read."});
  state.archive.mockResolvedValue(null);
  await check("a".repeat(40));
  expect(state.post).toHaveBeenCalledWith("token","acme/app","a".repeat(40),"neutral",expect.stringMatching(/^Partial review/),expect.stringContaining("cross-file route context is incomplete"),expect.any(String));
});

it("retains a deterministic block even when broader coverage is partial", async () => {
  state.files.mockResolvedValue({files:[{path:".env",content:"secret"}],listed:2,complete:false,coverage:"Partial diff."});
  state.scan.mockReturnValue({verdict:"block",findings:[{id:"secret",severity:"CRITICAL"}],filesChanged:1,routesChanged:0,trivial:false});
  await check("a".repeat(40));
  expect(state.post.mock.calls[0][3]).toBe("failure");
});

it("stores the review with its PR branch before posting the check (8B-1)", async () => {
  state.scan.mockReturnValue({verdict:"block",findings:[{id:"diff:x",severity:"CRITICAL",title:"t",detail:"d",file:"app/a.ts",evidence:"e"}],filesChanged:1,routesChanged:1,trivial:false});
  await check("A".repeat(40));
  expect(state.persist).toHaveBeenCalledWith({
    pullRequestNumber: 7, headSha: "a".repeat(40), headRef: "feature/orders", headRepository: "acme/app",
    sameRepository: true, title: "Add orders", url: "https://github.com/acme/app/pull/7",
    verdict: "block", coverageComplete: true,
    findings: [{ id: "diff:x", severity: "CRITICAL", title: "t", detail: "d", file: "app/a.ts", evidence: "e" }],
  });
  expect(state.persist.mock.invocationCallOrder[0]).toBeLessThan(state.post.mock.invocationCallOrder[0]);
});

it("posts nothing when the review cannot be stored, so the job retries (8B-1)", async () => {
  state.persist.mockRejectedValue(new Error("pull request check lease unavailable"));
  await expect(check("a".repeat(40))).rejects.toThrow("lease unavailable");
  expect(state.post).not.toHaveBeenCalled();
});

it("stores unknown PR metadata as null rather than guessing (8B-1)", async () => {
  state.pr.mockRejectedValue(new Error("GitHub 502"));
  await check("a".repeat(40));
  expect(state.persist.mock.calls[0][0]).toMatchObject({ headRef: null, headRepository: null, sameRepository: null, title: null, url: null });
});

// G1: the default branch's observed controls are guardrails; a PR that removes
// one from a route it touches fails, whatever the diff scan said.
const guarded = (over: object) => ({ path: "/api/orders", file: "app/a.ts", methods: ["GET"], tables: ["orders"], authenticated: true,
  machineGated: false, usesServiceRole: false, ownershipFiltered: false, identityReadable: true, ownershipReadable: true,
  dataReadable: true, machineGateReadable: true, serviceRoleReadable: true, identityGap: null, ownershipGap: null, dataGap: null,
  machineGateGap: null, via: [], ...over });

it("fails a PR that removes an observed session check, and stores the guardrail finding (G1)", async () => {
  state.routes.mockImplementation((files: { content: string }[]) =>
    [guarded({ authenticated: !files.some((f) => f.content === "ok") })]);
  await check("a".repeat(40));
  expect(state.post.mock.calls[0][3]).toBe("failure");
  const stored = state.persist.mock.calls[0][0];
  expect(stored.verdict).toBe("block");
  expect(stored.findings[0]).toMatchObject({ id: "guardrail:requires_signed_in_caller:/api/orders", severity: "CRITICAL", file: "app/a.ts" });
});

it("posts neutral, never green, when a guarded route can no longer be read (G1)", async () => {
  state.routes.mockImplementation((files: { content: string }[]) => files.some((f) => f.content === "ok")
    ? [guarded({ authenticated: false, identityReadable: false })] : [guarded({})]);
  await check("a".repeat(40));
  expect(state.post.mock.calls[0][3]).toBe("neutral");
  expect(state.post.mock.calls[0][5]).toContain("could not confirm");
});

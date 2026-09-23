import { beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";

const state = vi.hoisted(() => ({
  reads: { user_profiles: vi.fn(), repositories: vi.fn(), intelligence_scan_jobs: vi.fn(), intelligence_connections: vi.fn() },
  create: vi.fn(), token: vi.fn(), branch: vi.fn(), tree: vi.fn(), prFiles: vi.fn(), claim: vi.fn(), execute: vi.fn(),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof state.reads) => {
  const query = { eq: () => query, maybeSingle: () => state.reads[table]() };
  return { select: () => query };
} }) }));
vi.mock("@/lib/intelligence/tasks", () => ({ createIntelligenceTask: state.create }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: state.token, getBranchSha: state.branch,
  listTree: state.tree, listPullRequestFileNames: state.prFiles }));
vi.mock("./queue", () => {
  class PermanentJobError extends Error {}
  return { PermanentJobError, claimJob: state.claim, executeClaimedJob: state.execute, JobKind: z.string() };
});

import { deepScanCandidates, executeIntelligenceJob, pickDeepScanPaths, pickPullRequestPaths, runNextIntelligenceJob } from "./intelligenceWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job = {
  id: "11111111-1111-4111-8111-111111111111", user_id: "22222222-2222-4222-8222-222222222222",
  repository_id: "33333333-3333-4333-8333-333333333333", audit_run_id: null, kind: "intelligence",
  deduplication_key: "intel-deep:x", status: "running", attempts: 1, lease_token: "55555555-5555-4555-8555-555555555555",
  lease_until: "2099-01-01T00:00:00Z", checkpoint: 0,
} as unknown as ClaimedJob;
const head = "c".repeat(40);

beforeEach(() => {
  vi.clearAllMocks();
  state.reads.user_profiles.mockResolvedValue({ data: { github_installation_id: 42 }, error: null });
  state.reads.repositories.mockResolvedValue({ data: { full_name: "acme/app", selected: true, default_branch: "main" }, error: null });
  state.reads.intelligence_scan_jobs.mockResolvedValue({ data: { user_id: job.user_id, repository_id: job.repository_id, scan: "deep", pull_request_number: null, head_sha: null }, error: null });
  state.reads.intelligence_connections.mockResolvedValue({ data: { host: "codex", revoked_at: null, run_token_budget: 50000 }, error: null });
  state.token.mockResolvedValue("token");
  state.branch.mockResolvedValue(head);
  state.tree.mockResolvedValue([{ path: "app/api/orders/route.ts", size: 1 }, { path: "README.md", size: 1 }, { path: "middleware.ts", size: 1 }]);
  state.create.mockResolvedValue("99999999-9999-4999-8999-999999999999");
});

it("picks Next.js route handlers and middleware for a deep scan, bounded to 16", () => {
  const routes = Array.from({ length: 20 }, (_, i) => `app/api/r${String(i).padStart(2, "0")}/route.ts`);
  const picked = pickDeepScanPaths(["middleware.ts", "pages/api/login.js", "lib/x.ts", "node_modules/a/route.ts", ...routes], 0);
  expect(picked).toHaveLength(16);
  expect(picked[0]).toBe("middleware.ts");
  // Next.js 16 renamed middleware to proxy.
  expect(pickDeepScanPaths(["src/proxy.ts", "app/api/a/route.ts"], 0)).toEqual(["src/proxy.ts", "app/api/a/route.ts"]);
  expect(deepScanCandidates(["middleware.ts", "pages/api/login.js", "lib/x.ts", ...routes])).toHaveLength(22);
  expect(picked).not.toContain("lib/x.ts");
  expect(picked).not.toContain("node_modules/a/route.ts");
  // Rotation covers the rest in a later week.
  expect(pickDeepScanPaths(routes, 1)).toContain("app/api/r19/route.ts");
});

it("picks changed code files for a PR scan, skipping lockfiles and docs", () => {
  expect(pickPullRequestPaths(["app/page.tsx", "package-lock.json", "README.md", "supabase/migrations/1.sql"]))
    .toEqual(["app/page.tsx", "supabase/migrations/1.sql"]);
});

it("creates a deep-scan task for the approved host at the default branch head", async () => {
  await executeIntelligenceJob(job);
  expect(state.tree).toHaveBeenCalledWith("token", "acme/app", head);
  expect(state.create).toHaveBeenCalledWith(expect.objectContaining({ userId: job.user_id, repositoryId: job.repository_id,
    commit: head, host: "codex", paths: ["middleware.ts", "app/api/orders/route.ts"], key: `job:${job.id}` }));
  const { instruction } = state.create.mock.calls[0][0];
  expect(instruction).toContain("50000 tokens");
  expect(instruction).toContain("needs_human");
  expect(instruction.length).toBeLessThanOrEqual(2000);
});

it("creates a PR-scan task at the stored head from the changed files", async () => {
  state.reads.intelligence_scan_jobs.mockResolvedValue({ data: { user_id: job.user_id, repository_id: job.repository_id, scan: "pr", pull_request_number: 7, head_sha: head }, error: null });
  state.prFiles.mockResolvedValue({ paths: ["app/api/pay/route.ts", "README.md"], complete: true });
  await executeIntelligenceJob(job);
  expect(state.branch).not.toHaveBeenCalled();
  expect(state.create).toHaveBeenCalledWith(expect.objectContaining({ commit: head, paths: ["app/api/pay/route.ts"] }));
  expect(state.create.mock.calls[0][0].instruction).toContain("#7");
});

it("does nothing when the approval was revoked or nothing is reviewable", async () => {
  state.reads.intelligence_connections.mockResolvedValue({ data: { host: "codex", revoked_at: "2026-09-23T00:00:00Z", run_token_budget: 50000 }, error: null });
  await executeIntelligenceJob(job);
  state.reads.intelligence_connections.mockResolvedValue({ data: { host: "codex", revoked_at: null, run_token_budget: 50000 }, error: null });
  state.tree.mockResolvedValue([{ path: "README.md", size: 1 }]);
  await executeIntelligenceJob(job);
  expect(state.token).toHaveBeenCalledOnce();
  expect(state.create).not.toHaveBeenCalled();
  state.tree.mockResolvedValue([{ path: "middleware.ts", size: 1 }]);
  state.create.mockRejectedValue(new Error("intelligence_not_approved"));
  await expect(executeIntelligenceJob(job)).resolves.toBeUndefined();
  // The customer's monthly limit is reached: skip quietly, no retry storm.
  state.create.mockRejectedValue(new Error("intelligence_budget_exhausted"));
  await expect(executeIntelligenceJob(job)).resolves.toBeUndefined();
});

it("refuses changed context permanently and retries storage or GitHub failures", async () => {
  state.reads.repositories.mockResolvedValue({ data: { full_name: "acme/app", selected: false, default_branch: "main" }, error: null });
  await expect(executeIntelligenceJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  state.reads.repositories.mockResolvedValue({ data: { full_name: "acme/app", selected: true, default_branch: "main" }, error: null });
  state.reads.intelligence_scan_jobs.mockResolvedValue({ data: null, error: { message: "down" } });
  await expect(executeIntelligenceJob(job)).rejects.not.toBeInstanceOf(PermanentJobError);
  await expect(executeIntelligenceJob({ ...job, kind: "audit" } as ClaimedJob)).rejects.toBeInstanceOf(PermanentJobError);
});

it("claims at most one intelligence job", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextIntelligenceJob()).toBe(false);
  expect(state.claim).toHaveBeenCalledWith("intelligence");
  state.claim.mockResolvedValueOnce(job); state.execute.mockResolvedValueOnce(undefined);
  expect(await runNextIntelligenceJob()).toBe(true);
});

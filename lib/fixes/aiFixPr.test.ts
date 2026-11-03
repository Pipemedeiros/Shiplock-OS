import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const gh = vi.hoisted(() => ({ token: vi.fn(), file: vi.fn(), branchSha: vi.fn(), createBranch: vi.fn(), fileSha: vi.fn(),
  put: vi.fn(), open: vi.fn(), find: vi.fn() }));
import type { Mock } from "vitest";
const db = vi.hoisted(() => ({ reads: {} as Record<string, Mock<() => Promise<unknown>>>, filters: vi.fn() }));
const mechanical = vi.hoisted(() => vi.fn());
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: gh.token, getFile: gh.file, getBranchSha: gh.branchSha,
  createBranch: gh.createBranch, getFileSha: gh.fileSha, putFile: gh.put, openPullRequest: gh.open, findOpenPullRequestForBranch: gh.find }));
vi.mock("@/lib/intelligence/tasks", () => ({ mechanicalEdit: mechanical }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q = { select: () => q, eq: (k: string, v: unknown) => { db.filters(table, k, v); return q; }, maybeSingle: () => db.reads[table]() };
  return q;
} }) }));

import { openAiFixPr } from "./aiFixPr";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const user = "22222222-2222-4222-8222-222222222222", repoId = "33333333-3333-4333-8333-333333333333";
const taskId = "11111111-1111-4111-8111-111111111111", jobId = "44444444-4444-4444-8444-444444444444";
const before = "const config = { productionBrowserSourceMaps: true };\n";
const after = "const config = { productionBrowserSourceMaps: false };\n";
const task = (over: Record<string, unknown> = {}) => ({ id: taskId, repository_id: repoId, status: "proposal_received",
  idempotency_key: "manual-1", host: "codex",
  result: { summary: "Disable source maps @everyone <script>", model: "m", edits: [{ path: "next.config.ts", baseHash: sha(before), content: after }] },
  repositories: { full_name: "acme/app", default_branch: "main", selected: true }, ...over });

beforeEach(() => {
  vi.clearAllMocks();
  db.reads = { intelligence_tasks: vi.fn().mockResolvedValue({ data: task(), error: null }),
    user_profiles: vi.fn().mockResolvedValue({ data: { github_installation_id: 42 }, error: null }),
    intelligence_scan_jobs: vi.fn().mockResolvedValue({ data: null, error: null }),
    pull_request_reviews: vi.fn().mockResolvedValue({ data: null, error: null }) };
  gh.token.mockResolvedValue("t"); gh.file.mockResolvedValue(before); gh.find.mockResolvedValue(null);
  gh.branchSha.mockImplementation(async (_t: string, _r: string, b: string) => { if (b.startsWith("shiplock/")) throw new Error("404"); return "c".repeat(40); });
  gh.fileSha.mockResolvedValue("blob"); gh.open.mockResolvedValue("https://github.com/acme/app/pull/12");
  mechanical.mockReturnValue(true);
});

describe("openAiFixPr", () => {
  it("opens one PR with the AI's edits on a fresh branch off the default branch", async () => {
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/12", number: 12 });
    const branch = gh.createBranch.mock.calls[0][2];
    expect(branch).toMatch(/^shiplock\/ai-fix-[a-f0-9]{20}$/);
    expect(gh.put).toHaveBeenCalledWith("t", "acme/app", "next.config.ts", branch, after, "blob", expect.any(String));
    const [, , head, base, title, body] = gh.open.mock.calls[0];
    expect([head, base]).toEqual([branch, "main"]);
    expect(title).toContain("next.config.ts");
    // Model text is quoted inertly: no live mention or HTML survives into the PR.
    expect(body).not.toContain("@everyone");
    expect(body).not.toContain("<script>");
    expect(body).toMatch(/not run/i);
    expect(body).toMatch(/never merges/i);
    expect(db.filters).toHaveBeenCalledWith("intelligence_tasks", "user_id", user);
  });

  it("refuses when a file moved on since the AI read it, or the edit is no longer mechanical", async () => {
    gh.file.mockResolvedValue(before + "// changed\n");
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "source_changed" });
    gh.file.mockResolvedValue(before);
    mechanical.mockReturnValue(false);
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "not_fixable" });
    expect(gh.open).not.toHaveBeenCalled();
    expect(gh.put).not.toHaveBeenCalled();
  });

  it("refuses unanswered, foreign, or deselected work", async () => {
    db.reads.intelligence_tasks.mockResolvedValue({ data: task({ status: "needs_human" }), error: null });
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "finding_unavailable" });
    db.reads.intelligence_tasks.mockResolvedValue({ data: task({ repositories: { full_name: "acme/app", default_branch: "main", selected: false } }), error: null });
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "repository_unavailable" });
    db.reads.intelligence_tasks.mockResolvedValue({ data: task({ repository_id: "55555555-5555-4555-8555-555555555555" }), error: null });
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "repository_unavailable" });
  });

  it("targets a PR scan's own head branch, and refuses forks", async () => {
    db.reads.intelligence_tasks.mockResolvedValue({ data: task({ idempotency_key: `job:${jobId}` }), error: null });
    db.reads.intelligence_scan_jobs.mockResolvedValue({ data: { scan: "pr", pull_request_number: 7, head_sha: "d".repeat(40) }, error: null });
    db.reads.pull_request_reviews.mockResolvedValue({ data: { head_ref: "feature/x", same_repository: true }, error: null });
    await openAiFixPr(user, taskId, repoId);
    expect(gh.file).toHaveBeenCalledWith("t", "acme/app", "next.config.ts", "feature/x");
    expect(gh.open.mock.calls[0][3]).toBe("feature/x");
    db.reads.pull_request_reviews.mockResolvedValue({ data: { head_ref: "feature/x", same_repository: false }, error: null });
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "failed", code: "fork_pull_request" });
  });

  it("recovers the PR a lost response already opened, instead of duplicating it", async () => {
    gh.find.mockResolvedValue("https://github.com/acme/app/pull/9");
    expect(await openAiFixPr(user, taskId, repoId)).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/9", number: 9 });
    expect(gh.put).not.toHaveBeenCalled();
  });
});

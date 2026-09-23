import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

// 10B-1b: a customer's host submits a result for a durable task. ShipLock
// re-reads every cited file from GitHub at the pinned commit before storing.
const mocks = vi.hoisted(() => ({ task: vi.fn(), profile: vi.fn(), rpc: vi.fn(), file: vi.fn(), filters: vi.fn(), list: vi.fn() }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: vi.fn(async () => "token"), getFile: mocks.file }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc, from: (table: string) => {
  const chain = { select: () => chain, eq: (k: string, v: unknown) => { mocks.filters(table, k, v); return chain; },
    gt: (k: string, v: unknown) => { mocks.filters(table, `gt:${k}`, v); return chain; }, order: () => chain,
    limit: mocks.list, maybeSingle: table === "user_profiles" ? mocks.profile : mocks.task };
  return chain;
} }) }));

import { getIntelligenceTask, submitIntelligenceResult } from "./tasks";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const path = "next.config.ts";
const before = "const config = {\n  productionBrowserSourceMaps: true,\n};\nexport default config;\n";
const after = before.replace("productionBrowserSourceMaps: true", "productionBrowserSourceMaps: false");
const taskId = "11111111-1111-4111-8111-111111111111", userId = "22222222-2222-4222-8222-222222222222";
const repositoryId = "33333333-3333-4333-8333-333333333333", commit = "a".repeat(40);
const row = {
  id: taskId, user_id: userId, repository_id: repositoryId, commit_sha: commit, host: "api",
  instruction: "Propose the source-map fix.", sources: [{ path, sourceHash: hash(before) }], status: "pending",
  result: null, result_digest: null, expires_at: "2099-01-01T00:00:00.000Z", repositories: { full_name: "acme/app" },
};
const result = (over: Record<string, unknown> = {}) => ({
  version: 1, identity: { taskId, tenantId: userId, repositoryId, commit }, host: "api", model: "claude-haiku-4-5",
  status: "proposed", summary: "Disable production browser source maps.",
  citations: [{ path, sourceHash: hash(before), startLine: 2, endLine: 2, quote: "  productionBrowserSourceMaps: true," }],
  edits: [{ path, baseHash: hash(before), content: after }], usage: null, ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.task.mockResolvedValue({ data: row, error: null });
  mocks.profile.mockResolvedValue({ data: { github_installation_id: 42 }, error: null });
  mocks.file.mockResolvedValue(before);
  mocks.rpc.mockResolvedValue({ data: "accepted", error: null });
});

describe("getIntelligenceTask", () => {
  it("returns the owner's task with paths, hashes, and limits, never source or funding claims", async () => {
    const task = await getIntelligenceTask(userId, taskId);
    expect(task).toMatchObject({ identity: { taskId, tenantId: userId, repositoryId, commit }, host: "api",
      repository: "acme/app", permission: "propose_only", funding: "unverified", status: "pending",
      sources: [{ path, sourceHash: hash(before) }] });
    expect(JSON.stringify(task)).not.toContain("productionBrowserSourceMaps");
    expect(mocks.filters).toHaveBeenCalledWith("intelligence_tasks", "user_id", userId);
  });

  it("returns null for another tenant's or unknown task", async () => {
    mocks.task.mockResolvedValue({ data: null, error: null });
    expect(await getIntelligenceTask(userId, taskId)).toBeNull();
  });
});

describe("submitIntelligenceResult", () => {
  it("verifies citations against GitHub at the pinned commit, then stores a proposal only", async () => {
    const receipt = await submitIntelligenceResult(userId, taskId, result());
    expect(mocks.file).toHaveBeenCalledWith("token", "acme/app", path, commit);
    const [name, args] = mocks.rpc.mock.calls[0];
    expect(name).toBe("submit_intelligence_result");
    expect(args).toMatchObject({ p_user: userId, p_task: taskId, p_status: "proposal_received" });
    expect(args.p_digest).toMatch(/^[a-f0-9]{64}$/);
    expect(receipt).toEqual({ taskId, status: "proposal_received", outcome: "accepted",
      applied: false, prOpened: false, tests: "not_run", modelUsageVerified: false });
  });

  it.each([
    ["a forged quote", () => result({ citations: [{ ...result().citations[0], quote: "invented" }] }), "citation_mismatch"],
    ["a different commit", () => result({ identity: { taskId, tenantId: userId, repositoryId, commit: "b".repeat(40) } }), "scope_mismatch"],
    ["another host", () => result({ host: "codex" }), "scope_mismatch"],
    ["an unlisted file", () => result({ citations: [{ ...result().citations[0], path: "lib/auth.ts" }] }), "source_not_allowed"],
    ["a non-mechanical edit", () => result({ edits: [{ path, baseHash: hash(before), content: "export const isAdmin = () => true;" }] }), "edit_not_allowed"],
    ["an approval instruction", () => ({ ...result(), approve: true }), "invalid_result"],
  ])("rejects %s before storing", async (_name, build, code) => {
    await expect(submitIntelligenceResult(userId, taskId, build())).rejects.toThrow(code);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("rejects when the file at the commit no longer matches the task's hash", async () => {
    mocks.file.mockResolvedValue(before + "// changed\n");
    await expect(submitIntelligenceResult(userId, taskId, result())).rejects.toThrow("source_changed");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("stores an unavailable host answer without reading GitHub", async () => {
    const receipt = await submitIntelligenceResult(userId, taskId, result({ status: "unavailable", reason: "quota_exhausted", citations: [], edits: [] }));
    expect(mocks.file).not.toHaveBeenCalled();
    expect(receipt.status).toBe("unavailable");
  });

  it("surfaces the database's refusal code (expired, scope changed, already completed)", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "task_expired" } });
    await expect(submitIntelligenceResult(userId, taskId, result())).rejects.toThrow("task_expired");
  });
});

describe("createIntelligenceTask", () => {
  it("hashes each source from GitHub at the commit, so hashes are ShipLock's observation", async () => {
    mocks.task.mockResolvedValue({ data: { full_name: "acme/app" }, error: null });
    mocks.rpc.mockResolvedValue({ data: taskId, error: null });
    const { createIntelligenceTask } = await import("./tasks");
    expect(await createIntelligenceTask({ userId, repositoryId, commit, host: "api", instruction: "x", paths: [path], minutes: 10, key: "k1" })).toBe(taskId);
    const [name, args] = mocks.rpc.mock.calls[0];
    expect(name).toBe("create_intelligence_task");
    expect(args).toMatchObject({ p_user: userId, p_repository: repositoryId, p_commit: commit, p_host: "api", p_key: "k1",
      p_sources: [{ path, sourceHash: hash(before) }] });
    expect(mocks.file).toHaveBeenCalledWith("token", "acme/app", path, commit);
  });

  it("refuses an unselected repository or an unreadable file", async () => {
    const { createIntelligenceTask } = await import("./tasks");
    mocks.task.mockResolvedValue({ data: null, error: null });
    await expect(createIntelligenceTask({ userId, repositoryId, commit, host: "api", instruction: "x", paths: [path], minutes: 10, key: "k2" })).rejects.toThrow("repository_unavailable");
    mocks.task.mockResolvedValue({ data: { full_name: "acme/app" }, error: null });
    mocks.file.mockResolvedValue(null);
    await expect(createIntelligenceTask({ userId, repositoryId, commit, host: "api", instruction: "x", paths: [path], minutes: 10, key: "k3" })).rejects.toThrow("source_unreadable");
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("reports a missing or revoked approval distinctly (10B-2b gate)", async () => {
    mocks.task.mockResolvedValue({ data: { full_name: "acme/app" }, error: null });
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "intelligence not approved" } });
    const { createIntelligenceTask } = await import("./tasks");
    await expect(createIntelligenceTask({ userId, repositoryId, commit, host: "codex", instruction: "x", paths: [path], minutes: 10, key: "k4" })).rejects.toThrow("intelligence_not_approved");
  });
});

describe("listPendingIntelligenceTasks (10B-2a)", () => {
  it("returns only the caller's pending, unexpired tasks, newest first, without source", async () => {
    mocks.list.mockResolvedValue({ data: [
      { id: taskId, repository_id: repositoryId, commit_sha: commit, host: "claude-code", instruction: "x",
        expires_at: "2099-01-01T00:00:00.000Z", repositories: { full_name: "acme/app" } },
    ], error: null });
    const { listPendingIntelligenceTasks } = await import("./tasks");
    expect(await listPendingIntelligenceTasks(userId)).toEqual([{ taskId, repository: "acme/app", commit, host: "claude-code",
      instruction: "x", expiresAt: "2099-01-01T00:00:00.000Z" }]);
    expect(mocks.filters).toHaveBeenCalledWith("intelligence_tasks", "user_id", userId);
    expect(mocks.filters).toHaveBeenCalledWith("intelligence_tasks", "status", "pending");
    expect(mocks.filters).toHaveBeenCalledWith("intelligence_tasks", "gt:expires_at", expect.any(String));
  });
});

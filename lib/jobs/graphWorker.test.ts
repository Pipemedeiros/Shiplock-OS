import { beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";

const state = vi.hoisted(() => ({
  repository: vi.fn(),
  rpc: vi.fn(),
  input: vi.fn(),
  paths: vi.fn(),
  retire: vi.fn(),
  sources: vi.fn(),
  claim: vi.fn(),
  execute: vi.fn(),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => {
      const query = {
        eq: () => query,
        maybeSingle: state.repository,
      };
      return { select: () => query };
    },
    rpc: state.rpc,
  }),
}));
vi.mock("@/lib/graph/graphRun", () => ({
  loadGraphInput: state.input,
  canRetireGraphFindings: state.retire,
}));
vi.mock("@/lib/graph/attackPaths", () => ({ findAttackPaths: state.paths }));
vi.mock("@/lib/graph/repositorySource", () => ({
  loadSelectedRepositorySources: state.sources,
}));
vi.mock("./queue", () => {
  class PermanentJobError extends Error {}
  class StaleJobError extends PermanentJobError {}
  return {
    PermanentJobError,
    StaleJobError,
    claimJob: state.claim,
    executeClaimedJob: state.execute,
    JobKind: z.enum(["audit", "source", "monitor", "dependency", "graph", "pr-check"]),
  };
});

import { executeGraphJob, runNextGraphJob } from "./graphWorker";
import { PermanentJobError, StaleJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id: "11111111-1111-4111-8111-111111111111",
  user_id: "22222222-2222-4222-8222-222222222222",
  repository_id: "33333333-3333-4333-8333-333333333333",
  audit_run_id: null,
  deduplication_key: "graph:test",
  kind: "graph",
  status: "running",
  attempts: 1,
  lease_token: "44444444-4444-4444-8444-444444444444",
  lease_until: "2099-01-01T00:00:00Z",
  checkpoint: 0,
};

beforeEach(() => {
  vi.clearAllMocks();
  state.repository.mockResolvedValue({ data: { selected: true }, error: null });
  state.input.mockResolvedValue({
    repositoryId: job.repository_id,
    correlationScope: "repository-bound",
    sourceCoverage: "partial",
  });
  state.paths.mockReturnValue([{
    id: "path:one",
    severity: "CRITICAL",
    title: "Open path",
    consequence: "Close either side.",
    surfaces: ["source", "db", "source"],
  }]);
  state.retire.mockReturnValue(false);
  state.sources.mockResolvedValue(new Map([[job.repository_id, {
    repositoryFullName: "acme/app",
    snapshot: { recordedAt: "2026-09-22T00:00:00.000Z" },
  }]]));
  state.rpc.mockResolvedValue({ data: { total: 1, newCount: 1, resolvedCount: 0 }, error: null });
});

it("persists deterministic repository paths only through the live graph lease", async () => {
  await executeGraphJob(job);
  expect(state.rpc).toHaveBeenCalledWith("persist_repository_graph", {
    p_user: job.user_id,
    p_repository: job.repository_id,
    p_job: job.id,
    p_token: job.lease_token,
    p_source_revision: "2026-09-22T00:00:00.000Z",
    p_findings: [{
      finding_id: "path:one",
      severity: "CRITICAL",
      title: "Open path",
      consequence: "Close either side.",
      surfaces: ["source", "db"],
    }],
    p_allow_retire: false,
  });
});

it("cancels, not fails, a job for a repository the founder deselected or removed", async () => {
  for (const data of [{ selected: false }, null]) {
    state.repository.mockResolvedValue({ data, error: null });
    await expect(executeGraphJob(job)).rejects.toBeInstanceOf(StaleJobError);
  }
  expect(state.input).not.toHaveBeenCalled();
});

it("permanently refuses a deselected or mismatched repository", async () => {
  state.repository.mockResolvedValue({ data: null, error: null });
  await expect(executeGraphJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.input).not.toHaveBeenCalled();

  state.repository.mockResolvedValue({ data: { selected: true }, error: null });
  state.input.mockResolvedValue({ repositoryId: "55555555-5555-4555-8555-555555555555" });
  await expect(executeGraphJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  expect(state.rpc).not.toHaveBeenCalled();
});

it("retries a fenced persistence failure", async () => {
  state.rpc.mockResolvedValue({ data: null, error: { message: "private" } });
  await expect(executeGraphJob(job)).rejects.toThrow("could not be saved");
});

it("refuses to persist across a source revision change", async () => {
  state.sources
    .mockResolvedValueOnce(new Map([[job.repository_id, {
      repositoryFullName: "acme/app",
      snapshot: { recordedAt: "2026-09-22T00:00:00.000Z" },
    }]]))
    .mockResolvedValueOnce(new Map([[job.repository_id, {
      repositoryFullName: "acme/app",
      snapshot: { recordedAt: "2026-09-22T00:01:00.000Z" },
    }]]));
  await expect(executeGraphJob(job)).rejects.toThrow("changed during correlation");
  expect(state.rpc).not.toHaveBeenCalled();
});

it("claims at most one graph job", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextGraphJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job);
  state.execute.mockResolvedValue(undefined);
  expect(await runNextGraphJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job, [executeGraphJob]);
});

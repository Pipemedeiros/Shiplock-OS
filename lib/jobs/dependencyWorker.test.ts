import { beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";

const state = vi.hoisted(() => ({
  inventories: vi.fn(),
  collect: vi.fn(),
  rpc: vi.fn(),
  claim: vi.fn(),
  execute: vi.fn(),
}));
vi.mock("@/lib/graph/repositorySource", () => ({
  loadRepositoryDependencies: state.inventories,
}));
vi.mock("@/lib/runtime/zeroDay", () => ({ collectDependencyFindings: state.collect }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: state.rpc }) }));
vi.mock("./queue", () => {
  class PermanentJobError extends Error {}
  return {
    PermanentJobError,
    claimJob: state.claim,
    executeClaimedJob: state.execute,
    withLeaseHeartbeat: (_job: unknown, work: () => Promise<unknown>) => work(),
    JobKind: z.enum(["audit", "source", "monitor", "dependency", "graph", "pr-check"]),
  };
});

import { executeDependencyJob, runNextDependencyJob } from "./dependencyWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id: "11111111-1111-4111-8111-111111111111",
  user_id: "22222222-2222-4222-8222-222222222222",
  repository_id: "33333333-3333-4333-8333-333333333333",
  audit_run_id: null,
  deduplication_key: "dependency:test",
  kind: "dependency",
  status: "running",
  attempts: 1,
  lease_token: "44444444-4444-4444-8444-444444444444",
  lease_until: "2099-01-01T00:00:00Z",
  checkpoint: 0,
};
const inventory = {
  repositoryId: job.repository_id,
  repositoryFullName: "acme/app",
  sourceRevision: "2026-09-22T00:00:00.000Z",
  dependencies: [{ name: "left-pad", version: "1.0.0" }],
  completeness: "partial" as const,
};

beforeEach(() => {
  vi.clearAllMocks();
  state.inventories.mockResolvedValue([inventory]);
  state.collect.mockResolvedValue([{
    id: "acme/app::github:dep:left-pad:GHSA-x",
    severity: "CRITICAL",
    title: "RCE",
    consequence: "Upgrade.",
    packageName: "left-pad",
    version: "1.0.0",
    vulnId: "GHSA-x",
    cveId: "CVE-2026-1",
  }]);
  state.rpc.mockResolvedValue({ data: { total: 1, newCount: 1, resolvedCount: 0 }, error: null });
});

it("rechecks one repository and persists only through its live revision and lease", async () => {
  await executeDependencyJob(job);
  expect(state.collect).toHaveBeenCalledWith(inventory);
  expect(state.rpc).toHaveBeenCalledWith("persist_repository_dependency_findings", {
    p_user: job.user_id,
    p_repository: job.repository_id,
    p_job: job.id,
    p_token: job.lease_token,
    p_source_revision: inventory.sourceRevision,
    p_findings: [expect.objectContaining({
      finding_id: "acme/app::github:dep:left-pad:GHSA-x",
      vuln_id: "GHSA-x",
    })],
  });
});

// 110: a lockfile read in full can retire findings for versions it no
// longer installs, so a nonzero count is a success, not a malformed answer.
it("accepts findings the database retired for versions no longer installed", async () => {
  state.rpc.mockResolvedValue({ data: { total: 1, newCount: 0, resolvedCount: 2 }, error: null });
  await expect(executeDependencyJob(job)).resolves.toBeUndefined();
});

it("permanently refuses missing repository evidence and no-ops on observed emptiness", async () => {
  state.inventories.mockResolvedValue([]);
  await expect(executeDependencyJob(job)).rejects.toBeInstanceOf(PermanentJobError);
  state.inventories.mockResolvedValue([{ ...inventory, dependencies: [] }]);
  await expect(executeDependencyJob(job)).resolves.toBeUndefined();
  expect(state.collect).not.toHaveBeenCalled();
  expect(state.rpc).not.toHaveBeenCalled();
});

it("retries when source changes during the advisory request", async () => {
  state.inventories
    .mockResolvedValueOnce([inventory])
    .mockResolvedValueOnce([{ ...inventory, sourceRevision: "2026-09-22T00:01:00.000Z" }]);
  await expect(executeDependencyJob(job)).rejects.toThrow("changed during collection");
  expect(state.rpc).not.toHaveBeenCalled();
});

it("retries OSV and persistence failures", async () => {
  state.collect.mockRejectedValueOnce(new Error("OSV unavailable"));
  await expect(executeDependencyJob(job)).rejects.toThrow("OSV unavailable");
  state.collect.mockResolvedValueOnce([]);
  state.rpc.mockResolvedValueOnce({ data: null, error: { message: "private" } });
  await expect(executeDependencyJob(job)).rejects.toThrow("could not be saved");
});

it("claims at most one dependency job", async () => {
  state.claim.mockResolvedValueOnce(null);
  expect(await runNextDependencyJob()).toBe(false);
  state.claim.mockResolvedValueOnce(job);
  state.execute.mockResolvedValue(undefined);
  expect(await runNextDependencyJob()).toBe(true);
  expect(state.execute).toHaveBeenCalledWith(job, [executeDependencyJob]);
});

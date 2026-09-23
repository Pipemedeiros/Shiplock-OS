import { describe, expect, it, vi } from "vitest";

// 2F: traffic is account-scoped (one ingest token per account) and has no
// explicit repository binding, so it must never corroborate a repository's
// attack paths. Repository-scoped graph input is built only from repository
// sources; account-wide graph_facts (where traffic lives) are not read.
const reads = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  reads(table);
  const q = { select: () => q, eq: () => q,
    then: (resolve: (v: unknown) => unknown) => resolve({ data: [{ collector: "traffic", facts: { hotPaths: [{ path: "/login", suspiciousRequests: 9 }] } }], error: null }) };
  return q;
} }) }));
vi.mock("./repositorySource", () => ({
  loadRepositoryGraphSource: vi.fn(async () => ({ repositoryId: "r1", routes: [], sourceCoverage: "partial" })),
  loadRepositoryReachability: vi.fn(),
}));
vi.mock("./repositoryDatabase", () => ({
  loadRepositoryDatabaseEvidence: vi.fn(async () => ({ admission: "unknown", snapshots: {} })),
  projectRepositoryDatabaseEvidence: vi.fn(() => ({})),
}));
vi.mock("./narrative", () => ({ generateNarratives: vi.fn() }));

import { loadGraphInput } from "./graphRun";

describe("traffic stays account-scoped until explicitly bound (2F)", () => {
  it("never adds account traffic to a repository's graph input", async () => {
    const input = await loadGraphInput("u1", "r1");
    expect(input.trafficHotPaths).toBeUndefined();
    expect(reads).not.toHaveBeenCalledWith("graph_facts");
  });

  it("still carries traffic for account-scoped (repository-less) correlation", async () => {
    const input = await loadGraphInput("u1");
    expect(input.trafficHotPaths).toEqual([{ path: "/login", suspiciousRequests: 9 }]);
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

// A repository's graph run is corroborated only by traffic bound to that
// repository through a traffic site. Account-wide graph_facts (legacy,
// unbound traffic) are never read for a repository run.
const state = vi.hoisted(() => ({ reads: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  state.reads(table);
  const rows: Record<string, unknown[]> = {
    graph_facts: [{ collector: "traffic", facts: { hotPaths: [{ path: "/login", suspiciousRequests: 9 }] } }],
    traffic_alert_log: [{ source_id: "bad" }],
    traffic_blocklist: [],
    traffic_events: [{ path: "/api/orders" }, { path: "/api/orders" }],
    traffic_route_observations: [{ path: "/auth/v1/token", suspicious_requests: 25 }, { path: "/api/orders", suspicious_requests: 1 }],
  };
  const q: Record<string, unknown> = {};
  for (const m of ["select", "gte", "limit", "in"]) q[m] = () => q;
  q.eq = (k: string, v: unknown) => { state.filters(table, k, v); return q; };
  q.then = (resolve: (v: unknown) => unknown) => resolve({ data: rows[table] ?? [], error: null });
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

import { loadGraphInput } from "./graphRun";

beforeEach(() => { vi.clearAllMocks(); });

describe("traffic reaches a repository only through its bound sites", () => {
  it("uses only events bound to this repository, never account-wide graph facts", async () => {
    const input = await loadGraphInput("u1", "r1");
    // Snippet events and Supabase gateway observations for this repository, merged.
    expect(input.trafficHotPaths).toEqual([{ path: "/auth/v1/token", suspiciousRequests: 25 }, { path: "/api/orders", suspiciousRequests: 3 }]);
    expect(state.filters).toHaveBeenCalledWith("traffic_events", "repository_id", "r1");
    expect(state.filters).toHaveBeenCalledWith("traffic_route_observations", "repository_id", "r1");
    // X2: the snippet's own rows are already counted from traffic_events.
    expect(state.filters).toHaveBeenCalledWith("traffic_route_observations", "source", "supabase");
    expect(state.reads).not.toHaveBeenCalledWith("graph_facts");
  });

  it("still carries unbound traffic for account-scoped (repository-less) correlation", async () => {
    const input = await loadGraphInput("u1");
    expect(input.trafficHotPaths).toEqual([{ path: "/login", suspiciousRequests: 9 }]);
  });
});

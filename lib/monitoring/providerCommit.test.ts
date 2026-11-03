import { beforeEach, describe, expect, it, vi } from "vitest";

// The worker's commit capability calls the fenced SQL function with
// its own job identity and validates what comes back.
const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { fencedEdgeTrafficRecord, fencedProviderCommit, fencedProviderFailure } from "./providerCommit";

const commit = fencedProviderCommit("user-1", "job-1", "token-1");
const finding = { id: "rls:orders", severity: "CRITICAL" as const, title: "t", consequence: "c" };

beforeEach(() => { rpc.mockReset(); });

describe("fencedProviderCommit", () => {
  it("sends the job lease and connection identity with the result", async () => {
    rpc.mockResolvedValue({ data: [finding], error: null });
    const created = await commit({
      transport: "postgres-direct", identity: "a".repeat(64), facts: { policies: [] },
      findings: [finding], retire: true, snapshot: { scope: "db.example.com", failed: ["grants:"] },
    });
    expect(created).toEqual([finding]);
    expect(rpc).toHaveBeenCalledWith("persist_provider_monitor_result", {
      p_user: "user-1", p_job: "job-1", p_token: "token-1", p_transport: "postgres-direct",
      p_identity: "a".repeat(64), p_facts: { policies: [] }, p_findings: [finding], p_retire: true, p_unread: [],
      p_snapshot: { scope: "db.example.com", failed: ["grants:"] },
    });
  });

  it("sends null facts when the transport has none", async () => {
    rpc.mockResolvedValue({ data: [], error: null });
    await commit({ transport: "app-surface", identity: "https://app.example.com", findings: [], retire: true, unread: ["exposed:"], snapshot: { scope: "app.example.com", failed: ["exposed:"] } });
    expect(rpc.mock.calls[0][1]).toMatchObject({ p_facts: null, p_unread: ["exposed:"] });
  });

  it("throws when the fence rejects the commit", async () => {
    rpc.mockResolvedValue({ data: null, error: { message: "provider connection changed" } });
    await expect(commit({ transport: "vercel", identity: "b".repeat(64), findings: [], retire: false, snapshot: { scope: null, failed: [] } }))
      .rejects.toThrow("Provider result was not committed");
  });

  it("rejects a malformed response instead of alerting on it", async () => {
    rpc.mockResolvedValue({ data: [{ id: 1 }], error: null });
    await expect(commit({ transport: "vercel", identity: "b".repeat(64), findings: [], retire: false, snapshot: { scope: null, failed: [] } }))
      .rejects.toThrow("Provider result was not committed");
  });
});

describe("fencedProviderFailure", () => {
  it("records a failed read under the job lease", async () => {
    rpc.mockResolvedValue({ data: null, error: null });
    await fencedProviderFailure("user-1", "job-1", "token-1")("vercel", "auth_failed");
    expect(rpc).toHaveBeenCalledWith("record_provider_read_failure", {
      p_user: "user-1", p_job: "job-1", p_token: "token-1", p_transport: "vercel", p_scope: null, p_reason: "auth_failed",
    });
  });
  it("throws when the record was refused", async () => {
    rpc.mockResolvedValue({ data: null, error: { message: "monitor lease unavailable" } });
    await expect(fencedProviderFailure("user-1", "job-1", "token-1")("vercel", "failed")).rejects.toThrow();
  });
});

describe("fencedEdgeTrafficRecord", () => {
  it("records a gateway read under the job lease and throws when refused", async () => {
    rpc.mockResolvedValue({ data: null, error: null });
    await fencedEdgeTrafficRecord("user-1", "job-1", "token-1")("proj", true);
    expect(rpc).toHaveBeenCalledWith("record_edge_traffic_snapshot", {
      p_user: "user-1", p_job: "job-1", p_token: "token-1", p_project_ref: "proj", p_read: true,
    });
    rpc.mockResolvedValue({ data: null, error: { message: "monitor lease unavailable" } });
    await expect(fencedEdgeTrafficRecord("user-1", "job-1", "token-1")("proj", false)).rejects.toThrow();
  });
});

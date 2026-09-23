import { beforeEach, describe, expect, it, vi } from "vitest";

// 3F-C2c-2: the worker's commit capability calls the fenced SQL function with
// its own job identity and validates what comes back.
const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { fencedProviderCommit } from "./providerCommit";

const commit = fencedProviderCommit("user-1", "job-1", "token-1");
const finding = { id: "rls:orders", severity: "CRITICAL" as const, title: "t", consequence: "c" };

beforeEach(() => { rpc.mockReset(); });

describe("fencedProviderCommit", () => {
  it("sends the job lease and connection identity with the result", async () => {
    rpc.mockResolvedValue({ data: [finding], error: null });
    const created = await commit({
      transport: "postgres-direct", identity: "a".repeat(64), facts: { policies: [] },
      findings: [finding], retire: true,
    });
    expect(created).toEqual([finding]);
    expect(rpc).toHaveBeenCalledWith("persist_provider_monitor_result", {
      p_user: "user-1", p_job: "job-1", p_token: "token-1", p_transport: "postgres-direct",
      p_identity: "a".repeat(64), p_facts: { policies: [] }, p_findings: [finding], p_retire: true, p_unread: [],
    });
  });

  it("sends null facts when the transport has none", async () => {
    rpc.mockResolvedValue({ data: [], error: null });
    await commit({ transport: "app-surface", identity: "https://app.example.com", findings: [], retire: true, unread: ["exposed:"] });
    expect(rpc.mock.calls[0][1]).toMatchObject({ p_facts: null, p_unread: ["exposed:"] });
  });

  it("throws when the fence rejects the commit", async () => {
    rpc.mockResolvedValue({ data: null, error: { message: "provider connection changed" } });
    await expect(commit({ transport: "vercel", identity: "b".repeat(64), findings: [], retire: false }))
      .rejects.toThrow("Provider result was not committed");
  });

  it("rejects a malformed response instead of alerting on it", async () => {
    rpc.mockResolvedValue({ data: [{ id: 1 }], error: null });
    await expect(commit({ transport: "vercel", identity: "b".repeat(64), findings: [], retire: false }))
      .rejects.toThrow("Provider result was not committed");
  });
});

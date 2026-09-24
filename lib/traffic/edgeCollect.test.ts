import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ fetchLog: vi.fn(), bindings: vi.fn(), rpc: vi.fn(), profile: vi.fn() }));
vi.mock("@/lib/deep/supabaseMgmt", () => ({ fetchEdgeRequestLog: state.fetchLog }));
vi.mock("@/lib/deep/supabaseRepositoryBinding", () => ({ getSupabaseRepositoryBindings: state.bindings }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: state.rpc, from: () => {
  const q = { select: () => q, eq: () => q, maybeSingle: state.profile };
  return q;
} }) }));

import { collectSupabaseEdgeTraffic } from "./edgeCollect";

const t0 = Date.parse("2026-09-23T10:00:00Z");
const stuffing = Array.from({ length: 25 }, (_, i) => ({ ts: new Date(t0 + i * 1000).toISOString(), method: "POST",
  path: "/auth/v1/token?grant_type=password", status: 400, ip: "203.0.113.9" }));

beforeEach(() => {
  vi.clearAllMocks();
  process.env.ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef";
  state.fetchLog.mockResolvedValue({ ok: true, rows: stuffing });
  state.bindings.mockResolvedValue({ available: true, projectRef: "abcd", bindings: [{ repositoryId: "r1" }, { repositoryId: "r2" }] });
  state.rpc.mockResolvedValue({ data: 1, error: null });
  state.profile.mockResolvedValue({ data: { is_paid: true }, error: null });
});

describe("collectSupabaseEdgeTraffic (2F-4)", () => {
  it("stores judged paths for every repository the customer confirmed for this project", async () => {
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "read", repositories: 2, judgedSources: 1 });
    expect(state.rpc).toHaveBeenCalledWith("replace_traffic_observations",
      { p_user: "u1", p_repository: "r1", p_source: "supabase", p_paths: [{ path: "/auth/v1/token", suspiciousRequests: 25 }] });
    expect(JSON.stringify(state.rpc.mock.calls)).not.toContain("203.0.113.9");
  });

  it("follows the same traffic entitlement as the snippet (free vs paid is parked)", async () => {
    state.profile.mockResolvedValue({ data: { is_paid: false }, error: null });
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "not_enabled" });
    expect(state.fetchLog).not.toHaveBeenCalled();
  });

  it("does nothing without a confirmed repository for this exact project", async () => {
    state.bindings.mockResolvedValue({ available: true, projectRef: "other", bindings: [{ repositoryId: "r1" }] });
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "unbound" });
    expect(state.fetchLog).not.toHaveBeenCalled();
    state.bindings.mockResolvedValue({ available: true, projectRef: "abcd", bindings: [] });
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "unbound" });
  });

  it("reports unread, and keeps prior observations, when the log cannot be read", async () => {
    state.fetchLog.mockResolvedValue({ ok: false, rows: [] });
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "unread" });
    state.fetchLog.mockResolvedValue({ ok: true, rows: [{ garbage: 1 }] });
    expect(await collectSupabaseEdgeTraffic("u1", "tok", "abcd")).toEqual({ status: "unread" });
    expect(state.rpc).not.toHaveBeenCalled();
  });
});

import { describe, expect, it } from "vitest";
import { summarizeTrafficSources, type TrafficSourceInput } from "./sourceStatus";

// Per repository, where ShipLock's traffic view comes from, or
// that there is none. Nothing here is ever "quiet".
const base = (over: Partial<TrafficSourceInput> = {}): TrafficSourceInput => ({
  repositories: [{ id: "r1", fullName: "acme/app" }], sites: [], paid: true,
  supabase: { connected: true, projectRef: "proj", boundRepositoryIds: ["r1"] },
  edge: { completeness: "complete", observedAt: "2026-09-23T10:00:00.000Z", scope: "proj" }, ...over,
});
const one = (over: Partial<TrafficSourceInput> = {}) => summarizeTrafficSources(base(over))[0];

describe("summarizeTrafficSources", () => {
  it("read: the gateway log was read for a bound repository", () => {
    expect(one()).toMatchObject({ repository: "acme/app", sites: 0, gateway: "read", observedAt: "2026-09-23T10:00:00.000Z", hasSource: true });
  });
  it("unread: the last gateway read failed, and that is not a source", () => {
    expect(one({ edge: { completeness: "failed", observedAt: "2026-09-23T10:00:00.000Z", scope: "proj" } }))
      .toMatchObject({ gateway: "unread", hasSource: false });
  });
  it("never read: bound but no read yet", () => {
    expect(one({ edge: null })).toMatchObject({ gateway: "never_read", hasSource: false });
  });
  it("ignores a gateway read of a different project", () => {
    expect(one({ edge: { completeness: "complete", observedAt: "2026-09-23T10:00:00.000Z", scope: "other" } }).gateway).toBe("never_read");
  });
  it("unbound: Supabase connected but not linked to this repository", () => {
    expect(one({ supabase: { connected: true, projectRef: "proj", boundRepositoryIds: [] } })).toMatchObject({ gateway: "unbound", hasSource: false });
  });
  it("not connected: no Supabase connection", () => {
    expect(one({ supabase: null }).gateway).toBe("not_connected");
  });
  it("not enabled: traffic is not on for this account", () => {
    expect(one({ paid: false }).gateway).toBe("not_enabled");
  });
  it("snippet only: sites count as a source", () => {
    expect(one({ supabase: null, sites: [{ repositoryId: "r1" }, { repositoryId: "r1" }, { repositoryId: "r2" }] }))
      .toMatchObject({ sites: 2, gateway: "not_connected", hasSource: true });
  });
  it("none: no site and no read", () => {
    expect(one({ supabase: null })).toMatchObject({ sites: 0, hasSource: false });
  });
});

describe("getTrafficSources", () => {
  it("reads only the caller's rows and fails soft when bindings cannot be read", async () => {
    const { vi } = await import("vitest");
    const filters: unknown[][] = [];
    vi.resetModules();
    vi.doMock("@/lib/deep/supabaseRepositoryBinding", () => ({ getSupabaseRepositoryBindings: async () => { throw new Error("Binding read unavailable"); } }));
    vi.doMock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
      const q: Record<string, unknown> = {};
      Object.assign(q, {
        select: () => q, order: () => q, is: () => q,
        eq: (...a: unknown[]) => { filters.push([table, ...a]); return q; },
        maybeSingle: async () => ({ data: { is_paid: true }, error: null }),
        limit: async () => ({ data: [], error: null }),
        then: (resolve: (v: unknown) => unknown) => resolve({ data: [], error: null }),
      });
      return q;
    } }) }));
    const { getTrafficSources } = await import("./sourceStatus");
    expect(await getTrafficSources("u1")).toEqual({ available: false, items: [] });
    for (const table of ["repositories", "traffic_sites", "provider_snapshots"]) expect(filters).toContainEqual([table, "user_id", "u1"]);
    expect(filters).toContainEqual(["user_profiles", "id", "u1"]);
    vi.doUnmock("@/lib/supabase"); vi.doUnmock("@/lib/deep/supabaseRepositoryBinding");
  });
});

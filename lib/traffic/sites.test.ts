import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ site: vi.fn(), profile: vi.fn(), repo: vi.fn(), rpc: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: state.rpc, from: (table: string) => {
  const q = { select: () => q, eq: () => q, is: () => q,
    maybeSingle: table === "traffic_sites" ? state.site : table === "repositories" ? state.repo : state.profile };
  return q;
} }) }));

import { createTrafficSite, resolveTrafficToken } from "./sites";

const token = "11111111-1111-4111-8111-111111111111";
beforeEach(() => {
  vi.clearAllMocks();
  state.site.mockResolvedValue({ data: null, error: null });
  state.profile.mockResolvedValue({ data: null, error: null });
  state.repo.mockResolvedValue({ data: { id: "r1" }, error: null });
});

describe("traffic token resolution (2F-2a)", () => {
  it("binds a site token to its repository", async () => {
    state.site.mockResolvedValue({ data: { id: "s1", user_id: "u1", repository_id: "r1" }, error: null });
    state.profile.mockResolvedValue({ data: { id: "u1", email: "a@b.c", is_paid: true }, error: null });
    expect(await resolveTrafficToken(token)).toEqual({ userId: "u1", email: "a@b.c", siteId: "s1", repositoryId: "r1" });
  });

  it("leaves an account token unbound, so its traffic never reaches a repository", async () => {
    state.profile.mockResolvedValue({ data: { id: "u1", email: null, is_paid: true }, error: null });
    expect(await resolveTrafficToken(token)).toEqual({ userId: "u1", email: null, siteId: null, repositoryId: null });
  });

  it("drops a site whose repository is no longer selected, and any unpaid account (free vs paid is parked)", async () => {
    state.site.mockResolvedValue({ data: { id: "s1", user_id: "u1", repository_id: "r1" }, error: null });
    state.profile.mockResolvedValue({ data: { id: "u1", email: null, is_paid: true }, error: null });
    state.repo.mockResolvedValue({ data: null, error: null });
    expect(await resolveTrafficToken(token)).toBeNull();
    state.repo.mockResolvedValue({ data: { id: "r1" }, error: null });
    state.profile.mockResolvedValue({ data: { id: "u1", email: null, is_paid: false }, error: null });
    expect(await resolveTrafficToken(token)).toBeNull();
  });

  it("rejects a malformed token without a lookup", async () => {
    expect(await resolveTrafficToken("not-a-uuid")).toBeNull();
    expect(state.site).not.toHaveBeenCalled();
  });

  it("creates a site through the owner-scoped RPC", async () => {
    const siteId = "22222222-2222-4222-8222-222222222222";
    state.rpc.mockResolvedValue({ data: [{ site_id: siteId, ingest_token: token }], error: null });
    expect(await createTrafficSite("u1", "r1", "App.example.com")).toEqual({ siteId, ingestToken: token });
    expect(state.rpc).toHaveBeenCalledWith("create_traffic_site", { p_user: "u1", p_repository: "r1", p_host: "App.example.com" });
    state.rpc.mockResolvedValue({ data: null, error: { message: "host already bound" } });
    await expect(createTrafficSite("u1", "r2", "app.example.com")).rejects.toThrow("host_already_bound");
  });
});

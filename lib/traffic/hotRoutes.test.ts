import { beforeEach, describe, expect, it, vi } from "vitest";

// Q12-4: which observed routes each repository could get a rate-limit PR for.
const gh = vi.hoisted(() => ({ token: vi.fn(), tree: vi.fn() }));
const rows = vi.hoisted(() => ({ user_profiles: null as unknown, traffic_route_observations: [] as unknown, repositories: [] as unknown }));
vi.mock("@/lib/deep/github", () => ({ getInstallationToken: gh.token, listTree: gh.tree }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof rows) => {
  const q: Record<string, unknown> = {};
  const result = () => Promise.resolve({ data: rows[table], error: null });
  Object.assign(q, { select: () => q, eq: () => q, in: () => q, maybeSingle: result,
    then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => result().then(res, rej) });
  return q;
} }) }));

import { getHotRoutes } from "./hotRoutes";

beforeEach(() => {
  vi.clearAllMocks();
  rows.user_profiles = { github_installation_id: 42 };
  rows.traffic_route_observations = [
    { repository_id: "r1", path: "/api/orders/1", suspicious_requests: 30 },
    { repository_id: "r1", path: "/wp-login.php", suspicious_requests: 90 },
  ];
  rows.repositories = [{ id: "r1", full_name: "acme/app", default_branch: "main", selected: true }];
  gh.token.mockResolvedValue("tok");
  gh.tree.mockResolvedValue([{ path: "app/api/orders/[id]/route.ts" }]);
});

describe("getHotRoutes (Q12-4)", () => {
  it("returns matched routes per repository, read-only", async () => {
    expect(await getHotRoutes("u1")).toEqual({ r1: [{ file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 30 }] });
    expect(gh.tree).toHaveBeenCalledWith("tok", "acme/app", "main");
  });
  it("returns nothing without observations or an installation, and survives a GitHub error", async () => {
    rows.traffic_route_observations = [];
    expect(await getHotRoutes("u1")).toEqual({});
    rows.traffic_route_observations = [{ repository_id: "r1", path: "/api/orders/1", suspicious_requests: 3 }];
    gh.tree.mockRejectedValue(new Error("HTTP 502"));
    expect(await getHotRoutes("u1")).toEqual({});
    rows.user_profiles = { github_installation_id: null };
    expect(await getHotRoutes("u1")).toEqual({});
  });
  // X2: the snippet and the gateway are separate request streams for the
  // same route; one offer per route carries both counts.
  it("adds the snippet's and the gateway's counts for one route into one offer", async () => {
    rows.traffic_route_observations = [
      { repository_id: "r1", path: "/api/orders/1", suspicious_requests: 30 },
      { repository_id: "r1", path: "/api/orders/1", suspicious_requests: 12 },
    ];
    expect(await getHotRoutes("u1")).toEqual({ r1: [{ file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 42 }] });
  });
});

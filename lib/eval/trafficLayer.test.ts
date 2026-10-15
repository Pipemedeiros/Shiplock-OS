import { beforeEach, describe, expect, it, vi } from "vitest";

// The traffic leg, end to end with production's own functions (X2, Felipe
// 2026-10-12: "this is not even with traffic and the stack, so have a way to
// truly make sure this works"). Storage is an in-memory stand-in with the
// filters these reads use and the replace_traffic_observations semantics of
// migration 102 (the SQL suite checks the real function). From events the
// snippet recorded, through the daily write, to the rate-limit offer.
const db = vi.hoisted(() => ({ rows: {} as Record<string, Record<string, unknown>[]> }));
vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: vi.fn().mockResolvedValue("tok"),
  listTree: vi.fn().mockResolvedValue([{ path: "app/api/login/route.ts" }, { path: "app/api/orders/[id]/route.ts" }]),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  from: (table: string) => {
    const filters: ((row: Record<string, unknown>) => boolean)[] = [];
    let single = false;
    const q: Record<string, unknown> = {};
    const result = () => {
      const data = (db.rows[table] ?? []).filter((row) => filters.every((f) => f(row)));
      return Promise.resolve({ data: single ? data[0] ?? null : data, error: null });
    };
    Object.assign(q, {
      select: () => q, limit: () => q,
      eq: (k: string, v: unknown) => { filters.push((r) => r[k] === v); return q; },
      gte: (k: string, v: string) => { filters.push((r) => String(r[k]) >= v); return q; },
      in: (k: string, v: unknown[]) => { filters.push((r) => v.includes(r[k])); return q; },
      maybeSingle: () => { single = true; return result(); },
      then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => result().then(res, rej),
    });
    return q;
  },
  rpc: async (name: string, args: { p_user: string; p_repository: string; p_source: string; p_paths: { path: string; suspiciousRequests: number }[] }) => {
    if (name !== "replace_traffic_observations" || !["supabase", "snippet"].includes(args.p_source)) return { data: null, error: { message: "invalid traffic observations" } };
    const keep = (db.rows.traffic_route_observations ?? []).filter((r) =>
      !(r.user_id === args.p_user && r.repository_id === args.p_repository && r.source === args.p_source));
    db.rows.traffic_route_observations = [...keep, ...args.p_paths.map((p) => ({ user_id: args.p_user, repository_id: args.p_repository,
      source: args.p_source, path: p.path, suspicious_requests: p.suspiciousRequests, observed_at: new Date().toISOString() }))];
    return { data: args.p_paths.length, error: null };
  },
}) }));

const { syncSnippetObservations } = await import("@/lib/traffic/snippetObservations");
const { getHotRoutes } = await import("@/lib/traffic/hotRoutes");
const { collectTrafficFacts } = await import("@/lib/traffic/graphFacts");
const { computeSignals, detect } = await import("@/lib/traffic/detect");

const now = () => new Date().toISOString();
const event = (path: string, source_id: string, repository_id = "r1") =>
  ({ user_id: "u1", repository_id, source_id, path, created_at: now() });

describe("traffic: the snippet reaches the rate-limit offer", () => {
  beforeEach(() => {
    db.rows = {
      user_profiles: [{ id: "u1", github_installation_id: 42 }],
      repositories: [{ id: "r1", user_id: "u1", full_name: "acme/app", default_branch: "main", selected: true }],
      traffic_alert_log: [{ user_id: "u1", source_id: "bot", alerted_at: now() }],
      traffic_blocklist: [],
      traffic_events: [
        ...Array.from({ length: 40 }, () => event("/api/login", "bot")),
        event("/api/orders/7", "bot"),
        ...Array.from({ length: 500 }, () => event("/api/login", "a-real-user")),
        ...Array.from({ length: 9 }, () => event("/api/login", "bot", "r2")),
      ],
      traffic_route_observations: [],
    };
  });

  it("offers a rate limit for the route a flagged source hits, counting only this repository's flagged requests", async () => {
    expect(await getHotRoutes("u1")).toEqual({});
    expect(await syncSnippetObservations("u1", "r1")).toBe(2);
    expect(await getHotRoutes("u1")).toEqual({ r1: [
      { file: "app/api/login/route.ts", pattern: "/api/login", suspiciousRequests: 40 },
      { file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 1 },
    ] });
  });

  it("stops offering once the source is no longer flagged", async () => {
    await syncSnippetObservations("u1", "r1");
    db.rows.traffic_alert_log = [];
    expect(await syncSnippetObservations("u1", "r1")).toBe(0);
    expect(await getHotRoutes("u1")).toEqual({});
  });

  it("never counts a snippet request twice in the graph's urgency", async () => {
    await syncSnippetObservations("u1", "r1");
    db.rows.traffic_route_observations!.push({ user_id: "u1", repository_id: "r1", source: "supabase", path: "/api/login",
      suspicious_requests: 5, observed_at: now() });
    expect(await collectTrafficFacts("u1", "r1")).toEqual([
      { path: "/api/login", suspiciousRequests: 45 }, { path: "/api/orders/7", suspiciousRequests: 1 }]);
  });

  it("an id walk judged at ingest becomes the hot route on the file the audit read (P4)", async () => {
    const walk = Array.from({ length: 35 }, (_, i) => event(`/api/orders/${i + 100}`, "walker"));
    db.rows.traffic_events!.push(...walk);
    const decision = detect(computeSignals(walk.map((e) => ({ path: e.path, created_at: e.created_at })), Date.now()));
    expect(decision).toMatchObject({ action: "alert", reason: "Walking record ids: 35 different ids on /api/orders/:id in 5 minutes" });
    db.rows.traffic_alert_log!.push({ user_id: "u1", source_id: "walker", alerted_at: now(), reason: decision.reason, action: decision.action });
    await syncSnippetObservations("u1", "r1");
    expect((await getHotRoutes("u1")).r1).toContainEqual({ file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 36 });
  });
});


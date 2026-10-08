import { describe, expect, it } from "vitest";
import { buildRouteMap, compactRouteFacts, exposureOf, parseRouteFacts, simulateRequest, type MapRoute, type RouteMap } from "./routeMap";

const route = (path: string, tables: string[], over: Partial<MapRoute> = {}): MapRoute =>
  ({ path, file: `app${path}/route.ts`, tables, authenticated: true, ownershipFiltered: true, machineGated: false, ...over });
const pairs = (map: RouteMap) => map.edges.map((e) => [e.from, e.to]);
const edge = (map: RouteMap, from: string, to: string) => map.edges.find((e) => e.from === from && e.to === to);

const input = {
  routes: [route("/api/invoices", ["invoices"]), route("/api/export", ["invoices", "customers"]), route("/api/health", [])],
  tools: [{ id: "supabase", name: "Supabase", kind: "database" as const }, { id: "stripe", name: "Stripe", kind: "payments" as const },
    { id: "nextjs", name: "Next.js", kind: "framework" as const }],
  findings: [{ entry: "/api/invoices", severity: "WARNING" as const, title: "Signed-in callers are not limited to their own rows" }],
  hotFiles: ["app/api/export/route.ts"],
};

describe("route map (Q27)", () => {
  it("has a node only where a fact exists, and edges only for observed reads and controls", () => {
    const map = buildRouteMap(input);
    expect(map.nodes.map((n) => `${n.kind}:${n.label}`).sort()).toEqual([
      "control:Rows scoped to the caller", "control:Sign-in check",
      "provider:Stripe", "provider:Supabase",
      "route:/api/export", "route:/api/health", "route:/api/invoices",
      "table:customers", "table:invoices",
    ]);
    expect(pairs(map)).toEqual(expect.arrayContaining([
      ["route:/api/invoices", "control:session"], ["control:session", "control:scope"], ["control:scope", "table:invoices"],
      ["table:invoices", "provider:supabase"],
    ]));
    expect(map.edges.some((e) => e.from.includes("health") || e.to.includes("stripe"))).toBe(false);
  });

  it("marks findings, hot routes and the live connection state from facts", () => {
    const map = buildRouteMap(input);
    const byId = new Map(map.nodes.map((n) => [n.id, n]));
    expect(byId.get("route:/api/invoices")).toMatchObject({ finding: "WARNING", detail: expect.stringContaining("own rows") });
    expect(byId.get("route:/api/export")).toMatchObject({ hot: true });
    expect(byId.get("provider:supabase")).toMatchObject({ connection: "available" });
    expect(byId.get("provider:stripe")).toMatchObject({ connection: "coming_soon" });
  });

  it("links tables to the most specific database provider", () => {
    const map = buildRouteMap({ ...input, tools: [...input.tools, { id: "postgres", name: "Postgres", kind: "database" }] });
    expect(pairs(map)).toContainEqual(["table:invoices", "provider:supabase"]);
    expect(map.edges.some((e) => e.to === "provider:postgres")).toBe(false);
  });

  it("is deterministic and caps the graph", () => {
    expect(buildRouteMap(input)).toEqual(buildRouteMap(input));
    const many = buildRouteMap({ ...input, routes: Array.from({ length: 200 }, (_, i) => route(`/api/r${i}`, [`t${i % 90}`])) });
    expect(many.nodes.filter((n) => n.kind === "route")).toHaveLength(120);
    expect(many.truncated).toBe(true);
  });
});

describe("security view (Felipe 2026-10-01: distinguishable, auth to database, data flow)", () => {
  it("classifies each route by what it exposes, from facts only", () => {
    expect(exposureOf(route("/a", ["t"], { authenticated: false, ownershipFiltered: false }))).toBe("open");
    expect(exposureOf(route("/a", ["t"], { ownershipFiltered: false }))).toBe("unscoped");
    expect(exposureOf(route("/a", ["t"]))).toBe("scoped");
    expect(exposureOf(route("/a", ["t"], { machineGated: true, authenticated: false }))).toBe("secret");
    expect(exposureOf(route("/a", ["t"], { authenticated: false, identityReadable: false }))).toBe("unknown");
    expect(exposureOf(route("/a", []))).toBe("none");
  });

  it("routes data through the controls it passes, and colours each flow by risk", () => {
    const map = buildRouteMap({ ...input, routes: [
      route("/open", ["users"], { authenticated: false, ownershipFiltered: false }),
      route("/unscoped", ["orders"], { ownershipFiltered: false }),
      route("/scoped", ["orders"]),
      route("/hook", ["events"], { machineGated: true, authenticated: false, ownershipFiltered: false }),
    ] });
    expect(edge(map, "route:/open", "table:users")).toMatchObject({ kind: "flow", risk: "open" });
    expect(edge(map, "route:/unscoped", "control:session")).toMatchObject({ kind: "guard" });
    expect(edge(map, "control:session", "table:orders")).toMatchObject({ kind: "flow", risk: "unscoped" });
    expect(edge(map, "control:scope", "table:orders")).toMatchObject({ kind: "flow", risk: "guarded" });
    expect(edge(map, "route:/hook", "control:secret")).toMatchObject({ kind: "guard" });
    expect(edge(map, "control:secret", "table:events")).toMatchObject({ kind: "flow", risk: "guarded" });
    expect(map.nodes.find((n) => n.id === "route:/open")).toMatchObject({ exposure: "open" });
    expect(map.nodes.find((n) => n.id === "control:session")?.detail).toMatch(/2 routes/);
  });

  it("names no control a route was not read to have", () => {
    const map = buildRouteMap({ ...input, routes: [route("/open", ["users"], { authenticated: false, ownershipFiltered: false })] });
    expect(map.nodes.some((n) => n.kind === "control")).toBe(false);
  });
});

describe("route map, connections and simulation (Felipe 2026-09-30)", () => {
  const full = (path: string, via: string[], over: object = {}) => ({ ...route(path, ["invoices"]), via, identityReadable: true, ownershipReadable: true, machineGateReadable: true, ...over });

  it("keeps compact, code-free route facts from an audit, capped", () => {
    const facts = compactRouteFacts([{ ...full("/api/a", ["lib/auth.ts"]), methods: ["GET"], usesServiceRole: true, identityGap: "x" } as never]);
    expect(facts[0]).toEqual({ path: "/api/a", file: "app/api/a/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: true,
      machineGated: false, via: ["lib/auth.ts"], identityReadable: true, ownershipReadable: true, machineGateReadable: true });
    expect(compactRouteFacts(Array.from({ length: 900 }, (_, i) => full(`/r${i}`, []) as never))).toHaveLength(400);
  });

  it("connects routes through the code files they share, only when two or more share one", () => {
    const map = buildRouteMap({ ...input, routes: [full("/api/a", ["lib/auth.ts", "lib/only-a.ts"]), full("/api/b", ["lib/auth.ts"])] });
    expect(map.nodes.filter((n) => n.kind === "helper").map((n) => n.label)).toEqual(["lib/auth.ts"]);
    expect(pairs(map)).toEqual(expect.arrayContaining([["route:/api/a", "helper:lib/auth.ts"], ["route:/api/b", "helper:lib/auth.ts"]]));
    expect(edge(map, "route:/api/a", "helper:lib/auth.ts")).toMatchObject({ kind: "shared" });
    expect(map.nodes.find((n) => n.id === "helper:lib/auth.ts")?.detail).toMatch(/2 routes/);
  });

  it("does not call a route signed in where we read a method that never refuses (R1b)", () => {
    const unrefused = full("/api/feedback", [], { unrefusedMethods: ["GET"] });
    const behind = full("/api/admin", [], { unrefusedMethods: ["DELETE"], refusalGap: "a middleware at proxy.ts checks the caller on this path and may refuse first" });
    expect(exposureOf(unrefused)).toBe("open");
    expect(exposureOf(behind)).toBe("unknown");
    expect(simulateRequest(unrefused, "anonymous")).toMatchObject({ outcome: "reaches", reached: ["invoices"] });
    expect(simulateRequest(unrefused, "anonymous").steps.join(" ")).toMatch(/Nothing in its GET handler refuses a request with no sign-in/);
    expect(simulateRequest(behind, "anonymous")).toMatchObject({ outcome: "unknown" });
    const map = buildRouteMap({ ...input, routes: [unrefused], findings: [] });
    const node = map.nodes.find((n) => n.id === "route:/api/feedback")!;
    expect(node.detail).toMatch(/no refusal of a caller who is not signed in was read in GET/);
    expect(node.detail).not.toMatch(/Requires a signed-in caller/);
    expect(node.level).toBe("yellow");
    expect(edge(map, "route:/api/feedback", "control:session")).toBeUndefined();
    const [kept] = compactRouteFacts([unrefused]);
    expect(kept).toMatchObject({ unrefusedMethods: ["GET"] });
    expect(parseRouteFacts([behind])?.[0]).toMatchObject({ refusalGap: expect.stringMatching(/proxy\.ts/) });
  });

  it("simulates a request from facts only, and says unknown where a control was not read", () => {
    const open = full("/api/a", ["lib/db.ts"], { authenticated: false, ownershipFiltered: false });
    expect(simulateRequest(open, "anonymous")).toMatchObject({ outcome: "reaches", reached: ["invoices"] });
    const guarded = full("/api/b", ["lib/auth.ts"]);
    expect(simulateRequest(guarded, "anonymous")).toMatchObject({ outcome: "stopped" });
    expect(simulateRequest(full("/api/c", [], { ownershipFiltered: false }), "signed_in")).toMatchObject({ outcome: "reaches" });
    expect(simulateRequest(full("/api/c", []), "signed_in")).toMatchObject({ outcome: "scoped" });
    expect(simulateRequest(full("/api/d", [], { authenticated: false, identityReadable: false }), "anonymous")).toMatchObject({ outcome: "unknown" });
    const steps = simulateRequest(guarded, "anonymous").steps.join(" ");
    expect(steps).toMatch(/lib\/auth\.ts/);
    expect(steps).not.toMatch(/[–—]/);
  });
});

describe("label placement (UX pass 2026-10-01: no overlapping labels)", () => {
  it("keeps the higher priority label when two collide, and always keeps forced ones", async () => {
    const { placeLabels } = await import("./routeMap");
    const shown = placeLabels([
      { id: "a", x: 0, y: 0, w: 80, h: 14, priority: 1 },
      { id: "b", x: 10, y: 4, w: 80, h: 14, priority: 5 },
      { id: "c", x: 200, y: 0, w: 80, h: 14, priority: 1 },
      { id: "d", x: 400, y: 0, w: 40, h: 14, priority: 0, force: true },
    ]);
    expect([...shown].sort()).toEqual(["b", "c", "d"]);
  });
});

it("hides a label that would cover a forced one", async () => {
  const { placeLabels } = await import("./routeMap");
  expect([...placeLabels([{ id: "x", x: 0, y: 0, w: 50, h: 14, priority: 9 }, { id: "f", x: 5, y: 0, w: 50, h: 14, priority: 0, force: true }])]).toEqual(["f"]);
});

// A4 (Felipe 2026-10-07): the map shows only the routes that are wrong, red or
// yellow by degree. Red: a confirmed issue. Yellow: a candidate, or an open or
// unscoped exposure, with nothing confirmed. Safe and unreadable routes carry
// no level and leave the map.
describe("route levels", () => {
  const level = (map: RouteMap, path: string) => map.nodes.find((n) => n.id === `route:${path}`)?.level ?? null;
  it("marks red, yellow or nothing from findings and exposure", () => {
    const map = buildRouteMap({ ...input, routes: [
      route("/confirmed", ["orders"], { ownershipFiltered: false }),
      route("/candidate", ["orders"]),
      route("/open", ["orders"], { authenticated: false, ownershipFiltered: false }),
      route("/unscoped", ["orders"], { ownershipFiltered: false }),
      route("/safe", ["orders"]),
      route("/unread", ["orders"], { authenticated: false, identityReadable: false }),
    ], findings: [
      { entry: "/confirmed", severity: "WARNING", title: "t", confirmed: true },
      { entry: "/candidate", severity: "CRITICAL", title: "t", confirmed: false },
    ] });
    expect(["/confirmed", "/candidate", "/open", "/unscoped", "/safe", "/unread"].map((p) => level(map, p)))
      .toEqual(["red", "yellow", "yellow", "yellow", null, null]);
  });
});

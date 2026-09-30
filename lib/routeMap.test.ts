import { describe, expect, it } from "vitest";
import { buildRouteMap, type MapRoute } from "./routeMap";

const route = (path: string, tables: string[], over: Partial<MapRoute> = {}): MapRoute =>
  ({ path, file: `app${path}/route.ts`, tables, authenticated: true, ownershipFiltered: true, machineGated: false, ...over });

const input = {
  routes: [route("/api/invoices", ["invoices"]), route("/api/export", ["invoices", "customers"]), route("/api/health", [])],
  tools: [{ id: "supabase", name: "Supabase", kind: "database" as const }, { id: "stripe", name: "Stripe", kind: "payments" as const },
    { id: "nextjs", name: "Next.js", kind: "framework" as const }],
  findings: [{ entry: "/api/invoices", severity: "WARNING" as const, title: "Signed-in callers are not limited to their own rows" }],
  hotFiles: ["app/api/export/route.ts"],
};

describe("route map (Q27)", () => {
  it("has a node only where a fact exists, and edges only for observed reads", () => {
    const map = buildRouteMap(input);
    expect(map.nodes.map((n) => `${n.kind}:${n.label}`).sort()).toEqual([
      "provider:Stripe", "provider:Supabase",
      "route:/api/export", "route:/api/health", "route:/api/invoices",
      "table:customers", "table:invoices",
    ]);
    expect(map.edges).toEqual(expect.arrayContaining([
      ["route:/api/invoices", "table:invoices"], ["route:/api/export", "table:customers"], ["table:invoices", "provider:supabase"],
    ]));
    expect(map.edges.some(([a, b]) => a.includes("health") || b.includes("stripe"))).toBe(false);
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
    expect(map.edges).toContainEqual(["table:invoices", "provider:supabase"]);
    expect(map.edges.some(([, b]) => b === "provider:postgres")).toBe(false);
  });

  it("lays out deterministically in three layers and caps the graph", () => {
    const a = buildRouteMap(input);
    expect(buildRouteMap(input)).toEqual(a);
    const y = (kind: string) => a.nodes.filter((n) => n.kind === kind).map((n) => n.p[1]);
    expect(Math.max(...y("route"))).toBeLessThan(Math.min(...y("table")));
    expect(Math.max(...y("table"))).toBeLessThan(Math.min(...y("provider")));
    const many = buildRouteMap({ ...input, routes: Array.from({ length: 200 }, (_, i) => route(`/api/r${i}`, [`t${i % 90}`])) });
    expect(many.nodes.filter((n) => n.kind === "route")).toHaveLength(120);
    expect(many.truncated).toBe(true);
  });
});

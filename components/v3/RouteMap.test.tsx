import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { buildRouteMap, simulateRequest } from "@/lib/routeMap";
import { MapList, RouteMap, simulationPath } from "./RouteMap";

const map = buildRouteMap({
  routes: [
    { path: "/api/invoices", file: "app/api/invoices/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: false, machineGated: false },
    { path: "/api/public", file: "app/api/public/route.ts", tables: ["posts"], authenticated: false, ownershipFiltered: false, machineGated: false },
    { path: "/api/me", file: "app/api/me/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: true, machineGated: false },
  ],
  tools: [{ id: "supabase", name: "Supabase", kind: "database" }, { id: "stripe", name: "Stripe", kind: "payments" }],
  findings: [{ entry: "/api/invoices", severity: "CRITICAL", title: "Signed-in callers are not limited to their own rows" }],
  hotFiles: [],
});

// Felipe 2026-10-06: the map is an Obsidian-style graph, not 3D, inside v3's
// palette and fonts. Every node is still a labelled control, kind is carried
// by shape as well as colour, and the same facts are readable as a list.
describe("RouteMap, the Obsidian-style graph", () => {
  const html = renderToStaticMarkup(<RouteMap map={map} />);
  const visible = map.nodes.filter((n) => n.kind !== "helper");

  it("draws every visible node as a focusable, labelled button and opens on the worst finding", () => {
    expect(html.match(/<g[^>]*class="v3-map-node[^"]*"[^>]*role="button"/g)?.length
      ?? html.match(/<g[^>]*role="button"[^>]*class="v3-map-node/g)?.length).toBe(visible.length);
    expect(html).toContain('aria-label="route /api/invoices, Signed in, not limited to own rows, open critical finding"');
    expect(html).toMatch(/tabindex="0"/i);
    expect(html).toContain("Open critical finding");
    expect(html).toContain('href="/dashboard/risks"');
  });

  it("is a flat graph: no perspective projection, one SVG with pan and zoom controls", () => {
    expect(html.match(/<svg[^>]*class="v3-graph"/g)).toHaveLength(1);
    for (const label of ["Zoom in", "Zoom out", "Reset view"]) expect(html).toContain(`aria-label="${label}"`);
  });

  it("carries kind by shape, not colour alone", () => {
    expect(html).toMatch(/class="v3-map-node k-route[^"]*"[\s\S]*?<circle/);
    expect(html).toMatch(/class="v3-map-node k-table[^"]*"[\s\S]*?<rect/);
    expect(html).toMatch(/class="v3-map-node k-control[^"]*"[\s\S]*?<path/);
    expect(html).toContain("Security check");
  });

  it("names providers without a collector as coming soon, and has no dashes in its copy", () => {
    expect(html).toContain("Stripe · coming soon");
    expect(html.replace(/<[^>]+>/g, " ").replace(/−/g, "")).not.toMatch(/[–—]/);
  });

  it("keeps the request simulation, labelled as a simulation", () => {
    expect(html).toContain("Simulate a request");
    expect(html).toContain(">No sign-in<");
    expect(html).toContain("Not live traffic");
  });

  it("offers a list view of the same facts", () => {
    expect(html).toMatch(/<button[^>]*aria-pressed="false"[^>]*>List<\/button>/);
    const list = renderToStaticMarkup(<MapList map={map} visible={new Set(visible.map((n) => n.id))} selected="" onSelect={() => {}} />);
    expect(list).toContain("No sign in");
    expect(list).toMatch(/<button[^>]*>\/api\/public<\/button>/);
    expect(list).toContain("reaches posts");
  });

  it("walks a simulated request along the map's own edges only", () => {
    const route = map.nodes.find((n) => n.id === "route:/api/invoices")!;
    const sim = simulateRequest(route.fact!, "signed_in");
    expect(simulationPath(map, route.id, sim)).toEqual(["route:/api/invoices", "control:session", "table:invoices"]);
    expect(simulationPath(map, route.id, simulateRequest(route.fact!, "anonymous"))).toEqual(["route:/api/invoices", "control:session"]);
    // The sign-in check is shared with a scoped route; only that route goes on to the scope check.
    const me = map.nodes.find((n) => n.id === "route:/api/me")!;
    expect(simulationPath(map, me.id, simulateRequest(me.fact!, "signed_in"))).toEqual(["route:/api/me", "control:session", "control:scope", "table:invoices"]);
  });
});

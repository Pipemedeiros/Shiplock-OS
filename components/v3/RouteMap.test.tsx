import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { buildRouteMap, simulateRequest, withSources } from "@/lib/routeMap";
import { MapList, RouteMap, simulationPath } from "./RouteMap";

const map = buildRouteMap({
  routes: [
    { path: "/api/invoices", file: "app/api/invoices/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: false, machineGated: false },
    { path: "/api/public", file: "app/api/public/route.ts", tables: ["posts"], authenticated: false, ownershipFiltered: false, machineGated: false },
    { path: "/api/me", file: "app/api/me/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: true, machineGated: false },
  ],
  tools: [{ id: "supabase", name: "Supabase", kind: "database" }, { id: "stripe", name: "Stripe", kind: "payments" }],
  findings: [{ entry: "/api/invoices", severity: "CRITICAL", title: "Signed-in callers are not limited to their own rows", confirmed: true }],
  hotFiles: [],
});

// Felipe 2026-10-06: the map is an Obsidian-style graph, not 3D, inside v3's
// palette and fonts. Every node is still a labelled control, kind is carried
// by shape as well as colour, and the same facts are readable as a list.
describe("RouteMap, the Obsidian-style graph", () => {
  const html = renderToStaticMarkup(<RouteMap map={map} />);
  // Only routes that are wrong (red or yellow) and what their requests reach.
  const reach = new Set(map.nodes.filter((n) => n.kind === "route" && n.level).map((n) => n.id));
  for (let changed = true; changed;) {
    changed = false;
    for (const e of map.edges) if (reach.has(e.from) && !reach.has(e.to) && e.kind !== "shared") { reach.add(e.to); changed = true; }
  }
  const visible = map.nodes.filter((n) => reach.has(n.id));

  it("draws every visible node as a focusable, labelled button and opens on the worst finding", () => {
    expect(html.match(/<g[^>]*class="v3-map-node[^"]*"[^>]*role="button"/g)?.length
      ?? html.match(/<g[^>]*role="button"[^>]*class="v3-map-node/g)?.length).toBe(visible.length);
    expect(html).toContain('aria-label="route /api/invoices, Signed in, not limited to own rows, confirmed issue"');
    expect(html).toMatch(/tabindex="0"/i);
    expect(html).toContain("Confirmed issue");
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

  it("keeps services nothing wrong reaches off the map (Stack lists every provider), and has no dashes in its copy", () => {
    expect(html).not.toContain("Stripe");
    expect(html).toContain("Supabase");
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
    expect(list).toContain("Candidate or open way to data");
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

  // Felipe 2026-10-07: the map shows only what is wrong, red or yellow.
  it("leaves safe routes off the map and colours the rest by degree", () => {
    expect(html).not.toContain("route /api/me");
    expect(html).toMatch(/class="v3-map-node k-route[^"]*"[^>]*aria-label="route \/api\/invoices[^"]*confirmed issue"/);
    expect(html).toMatch(/aria-label="route \/api\/public[^"]*candidate"/);
    expect(html).not.toContain("Only exposed paths");
    expect(html).toContain("Confirmed issue");
  });

  it("says plainly when no route is wrong, without calling the app safe", () => {
    const quiet = buildRouteMap({ routes: [{ path: "/api/me", file: "app/api/me/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: true, machineGated: false }],
      tools: [], findings: [], hotFiles: [] });
    const out = renderToStaticMarkup(<RouteMap map={quiet} />);
    expect(out).toContain("No route with an issue or an open way to data in this audit");
    expect(out).not.toMatch(/secure|safe/i);
  });
});

// Traffic page (Felipe 2026-10-16): the sources that attacked a route, on the graph.
describe("RouteMap with flagged traffic sources", () => {
  const attacked = withSources(map, [{ alias: "Source a1b2", kinds: ["Walking record ids"], requests: 31, status: "flagged",
    routes: [{ file: "app/api/invoices/route.ts" }] }]);
  const html = renderToStaticMarkup(<RouteMap map={attacked} />);

  it("draws a source as a labelled control, by shape, with its attack edge and a legend entry", () => {
    expect(html).toContain('aria-label="traffic source Source a1b2"');
    expect(html).toContain('data-edge="attack"');
    expect(html).toContain("Traffic source");
    expect(html).toContain("Attack request");
  });

  it("lists sources and the routes they hit in the List view", () => {
    const visible = new Set(attacked.nodes.map((n) => n.id));
    const list = renderToStaticMarkup(<MapList map={attacked} visible={visible} selected="" onSelect={() => {}} />);
    expect(list).toContain("Traffic sources");
    expect(list).toContain("Source a1b2");
    expect(list).toContain("/api/invoices");
  });

  it("shows an attacked route even when the audit read nothing wrong on it", () => {
    const quiet = buildRouteMap({ routes: [{ path: "/api/me", file: "app/api/me/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: true, machineGated: false }],
      tools: [], findings: [], hotFiles: [] });
    const out = renderToStaticMarkup(<RouteMap map={withSources(quiet, [{ alias: "Source ffee", kinds: ["Request flood"], requests: 140,
      status: "blocked", routes: [{ file: "app/api/me/route.ts" }] }])} />);
    expect(out).not.toContain("No route with an issue");
    expect(out).toContain('aria-label="traffic source Source ffee"');
    expect(out).toContain('aria-label="route /api/me, Scoped to the caller, attacked"');
  });
});


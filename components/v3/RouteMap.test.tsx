import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { buildRouteMap } from "@/lib/routeMap";
import { project, RouteMap, simulationPath } from "./RouteMap";
import { simulateRequest } from "@/lib/routeMap";

const map = buildRouteMap({
  routes: [{ path: "/api/invoices", file: "app/api/invoices/route.ts", tables: ["invoices"], authenticated: true, ownershipFiltered: false, machineGated: false }],
  tools: [{ id: "supabase", name: "Supabase", kind: "database" }, { id: "stripe", name: "Stripe", kind: "payments" }],
  findings: [{ entry: "/api/invoices", severity: "CRITICAL", title: "Signed-in callers are not limited to their own rows" }],
  hotFiles: [],
});

describe("RouteMap (Q27)", () => {
  const html = renderToStaticMarkup(<RouteMap map={map} />);

  it("renders every node as a labelled button and opens on the worst finding", () => {
    expect(html.match(/<button[^>]*class="v3-map-node/g)).toHaveLength(map.nodes.length);
    expect(html).toContain('aria-label="route /api/invoices, Signed in, not limited to own rows, open critical finding"');
    expect(html).toContain("Open critical finding");
    expect(html).toContain('href="/dashboard/risks"');
  });

  it("names providers without a collector as coming soon, and has no dashes in its copy", () => {
    expect(html).toContain("Stripe · coming soon");
    expect(html.replace(/<[^>]+>/g, " ").replace("−", "")).not.toMatch(/[–—]/);
  });

  it("projects farther points smaller", () => {
    const view = { yaw: 0, pitch: 0, zoom: 1 };
    expect(project([0, 0, 300], view, 0, 0, 1).f).toBeLessThan(project([0, 0, -300], view, 0, 0, 1).f);
  });

  it("offers the request simulation on a route, labelled as a simulation", () => {
    expect(html).toContain("Simulate a request");
    expect(html).toContain(">No sign-in<");
    expect(html).toContain("Not live traffic");
  });

  it("walks a simulated request along the map's own edges only", () => {
    const route = map.nodes.find((n) => n.kind === "route")!;
    const sim = simulateRequest(route.fact!, "signed_in");
    // Signed in and not scoped: through the sign-in check straight to the table.
    expect(simulationPath(map, route.id, sim)).toEqual(["route:/api/invoices", "control:session", "table:invoices"]);
    // No sign-in: stopped at the sign-in check.
    expect(simulationPath(map, route.id, simulateRequest(route.fact!, "anonymous"))).toEqual(["route:/api/invoices", "control:session"]);
  });
});

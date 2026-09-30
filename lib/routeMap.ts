import type { StackKind } from "@/lib/agent/stack";

/**
 * The dashboard's 3D route map (Q27, Felipe 2026-09-29: an Obsidian-like
 * graph after the scan). Pure: the audit's own facts in, nodes and edges out.
 * A node exists only where a fact does (a route the audit read, a table it
 * saw a route reach, a provider inferred from code); an edge is an observed
 * read, never a guess. Layout is deterministic so two visits look the same:
 * routes above, tables in the middle, providers below, each on a spiral.
 */
export type MapRoute = { path: string; file: string; tables: string[]; authenticated: boolean; ownershipFiltered: boolean; machineGated: boolean };
export type MapTool = { id: string; name: string; kind: StackKind };
export type MapFinding = { entry: string | null; severity: "CRITICAL" | "WARNING" | "INFO"; title: string };

export type MapNode = {
  id: string;
  kind: "route" | "table" | "provider";
  label: string;
  p: [number, number, number];
  detail: string;
  file?: string;
  finding?: MapFinding["severity"];
  hot?: boolean;
  connection?: "available" | "coming_soon";
};
export type RouteMap = { nodes: MapNode[]; edges: [string, string][]; truncated: boolean };

const MAX_ROUTES = 120;
const MAX_TABLES = 80;
const LIVE = new Set(["supabase", "supabase-auth", "postgres", "prisma", "drizzle"]);
const PROVIDER_KINDS: StackKind[] = ["database", "auth", "payments", "hosting", "storage", "email", "ai"];
const DATABASE_IDS = ["supabase", "postgres", "prisma", "drizzle", "firebase", "mongodb"];

function spiral(count: number, radius: number, y: number, jitter: number): [number, number, number][] {
  const golden = Math.PI * (3 - Math.sqrt(5));
  return Array.from({ length: count }, (_, i) => {
    const r = radius * Math.sqrt((i + 0.5) / Math.max(1, count));
    const a = i * golden;
    return [Math.round(r * Math.cos(a)), Math.round(y + ((i % 3) - 1) * jitter), Math.round(r * Math.sin(a))];
  });
}

const rank = { CRITICAL: 0, WARNING: 1, INFO: 2 } as const;

export function buildRouteMap(input: { routes: MapRoute[]; tools: MapTool[]; findings: MapFinding[]; hotFiles: string[] }): RouteMap {
  const hot = new Set(input.hotFiles);
  const worst = new Map<string, MapFinding>();
  for (const f of input.findings) {
    if (!f.entry) continue;
    const prior = worst.get(f.entry);
    if (!prior || rank[f.severity] < rank[prior.severity]) worst.set(f.entry, f);
  }
  // Findings and hot routes first, so a cap never hides what matters.
  const ordered = [...input.routes].sort((a, b) =>
    Number(!worst.has(a.path) && !hot.has(a.file)) - Number(!worst.has(b.path) && !hot.has(b.file)) || a.path.localeCompare(b.path));
  const routes = ordered.slice(0, MAX_ROUTES);
  const tables = [...new Set(routes.flatMap((r) => r.tables))].sort().slice(0, MAX_TABLES);
  const tableSet = new Set(tables);
  const providers = input.tools.filter((t) => PROVIDER_KINDS.includes(t.kind)).sort((a, b) => a.id.localeCompare(b.id));
  // The most specific database wins (Supabase over the Postgres it runs on).
  const database = DATABASE_IDS.map((id) => providers.find((t) => t.id === id)).find(Boolean);

  const nodes: MapNode[] = [];
  const routeSpots = spiral(routes.length, 150 + routes.length * 3, -130, 22);
  routes.forEach((r, i) => {
    const finding = worst.get(r.path);
    const controls = r.machineGated ? "Requires a secret or signature." : [
      r.authenticated ? "Requires a signed-in caller." : "No sign-in check read.",
      r.tables.length ? (r.ownershipFiltered ? "Scoped to the caller's rows." : "Not scoped to the caller's rows.") : "Reaches no table we read.",
    ].join(" ");
    nodes.push({ id: `route:${r.path}`, kind: "route", label: r.path, p: routeSpots[i], file: r.file,
      detail: finding ? `${finding.title}. ${controls}` : controls,
      ...(finding ? { finding: finding.severity } : {}), ...(hot.has(r.file) ? { hot: true } : {}) });
  });
  const tableSpots = spiral(tables.length, 120 + tables.length * 3, 40, 14);
  tables.forEach((t, i) => {
    const readers = routes.filter((r) => r.tables.includes(t)).length;
    nodes.push({ id: `table:${t}`, kind: "table", label: t, p: tableSpots[i], detail: `Reached by ${readers} route${readers === 1 ? "" : "s"}.` });
  });
  const providerSpots = spiral(providers.length, 110, 190, 0);
  providers.forEach((t, i) => {
    const connection = LIVE.has(t.id) ? "available" : "coming_soon";
    nodes.push({ id: `provider:${t.id}`, kind: "provider", label: t.name, p: providerSpots[i], connection,
      detail: connection === "available" ? "Inferred from your code. A read-only live connection is available." : "Inferred from your code. Live connection coming soon." });
  });

  const edges: [string, string][] = [];
  for (const r of routes) for (const t of r.tables) if (tableSet.has(t)) edges.push([`route:${r.path}`, `table:${t}`]);
  if (database) for (const t of tables) edges.push([`table:${t}`, `provider:${database.id}`]);
  relax(nodes, edges);
  return { nodes, edges, truncated: input.routes.length > routes.length || tableSet.size < new Set(routes.flatMap((r) => r.tables)).size };
}

const LAYER_Y = { route: -120, table: 40, provider: 170 } as const;
const FIT_RADIUS = 240;

/**
 * A small deterministic force layout, so routes that share tables sit
 * together (the Obsidian look) instead of a hairball. Starts from the spiral,
 * fixed iteration count, no randomness; then scaled to a fixed radius so the
 * stage can fit any repository.
 */
function relax(nodes: MapNode[], edges: [string, string][]): void {
  const index = new Map(nodes.map((n, i) => [n.id, i]));
  const pos = nodes.map((n) => [...n.p] as [number, number, number]);
  const links = edges.map(([a, b]) => [index.get(a)!, index.get(b)!] as const);
  const n = nodes.length;
  for (let step = 0; step < 160; step++) {
    const force = pos.map(() => [0, 0, 0]);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = pos[i][0] - pos[j][0], dy = pos[i][1] - pos[j][1], dz = pos[i][2] - pos[j][2];
        const d2 = Math.max(25, dx * dx + dy * dy + dz * dz);
        const push = 1800 / d2;
        const inv = push / Math.sqrt(d2);
        force[i][0] += dx * inv; force[i][1] += dy * inv; force[i][2] += dz * inv;
        force[j][0] -= dx * inv; force[j][1] -= dy * inv; force[j][2] -= dz * inv;
      }
    }
    for (const [a, b] of links) {
      const dx = pos[b][0] - pos[a][0], dy = pos[b][1] - pos[a][1], dz = pos[b][2] - pos[a][2];
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy + dz * dz));
      const pull = (d - 70) * 0.02 / d;
      force[a][0] += dx * pull; force[a][1] += dy * pull; force[a][2] += dz * pull;
      force[b][0] -= dx * pull; force[b][1] -= dy * pull; force[b][2] -= dz * pull;
    }
    const cool = 1 - step / 160;
    for (let i = 0; i < n; i++) {
      force[i][1] += (LAYER_Y[nodes[i].kind] - pos[i][1]) * 0.05;
      force[i][0] -= pos[i][0] * 0.004; force[i][2] -= pos[i][2] * 0.004;
      for (let k = 0; k < 3; k++) pos[i][k] += Math.max(-12, Math.min(12, force[i][k] * 4)) * cool;
    }
  }
  // Fit the bulk, not the outliers: scale the 90th-percentile radius to the
  // stage, then pull any far node in to the edge.
  const radii = pos.map(([x, y, z]) => Math.sqrt(x * x + y * y + z * z)).sort((a, b) => a - b);
  const bulk = Math.max(1, radii[Math.floor((radii.length - 1) * 0.9)] ?? 1);
  const fit = Math.min(2.5, FIT_RADIUS / bulk);
  nodes.forEach((node, i) => {
    const r = Math.sqrt(pos[i][0] ** 2 + pos[i][1] ** 2 + pos[i][2] ** 2) * fit;
    const clamp = r > FIT_RADIUS * 1.15 ? (FIT_RADIUS * 1.15) / r : 1;
    node.p = pos[i].map((v) => Math.round(v * fit * clamp)) as [number, number, number];
  });
}

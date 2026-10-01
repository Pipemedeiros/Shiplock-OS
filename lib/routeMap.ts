import { z } from "zod";
import type { StackKind } from "@/lib/agent/stack";

/**
 * The dashboard's 3D route map (Q27, Felipe 2026-09-29: an Obsidian-like
 * graph after the scan). Pure: the audit's own facts in, nodes and edges out.
 * A node exists only where a fact does (a route the audit read, a table it
 * saw a route reach, a provider inferred from code); an edge is an observed
 * read, never a guess. Layout is deterministic so two visits look the same:
 * routes above, tables in the middle, providers below, each on a spiral.
 */
export type MapRoute = {
  path: string; file: string; tables: string[]; authenticated: boolean; ownershipFiltered: boolean; machineGated: boolean;
  /** Code files the route executes (auth helpers, database clients); links routes to each other. */
  via?: string[];
  identityReadable?: boolean; ownershipReadable?: boolean; machineGateReadable?: boolean;
};
export type MapTool = { id: string; name: string; kind: StackKind };
export type MapFinding = { entry: string | null; severity: "CRITICAL" | "WARNING" | "INFO"; title: string };

export type Exposure = "open" | "unscoped" | "scoped" | "secret" | "unknown" | "none";
export type Risk = "open" | "unknown" | "unscoped" | "guarded";
/** guard: route into a control; flow: data reaching a table (with its risk); shared: code; store: table to its database. */
export type MapEdge = { from: string; to: string; kind: "guard" | "flow" | "shared" | "store"; risk?: Risk };

/** What a route exposes, from the controls the audit read (never guessed). */
export function exposureOf(r: MapRoute): Exposure {
  if (r.tables.length === 0) return "none";
  if (r.machineGated) return r.machineGateReadable === false ? "unknown" : "secret";
  if (!r.authenticated) return r.identityReadable === false ? "unknown" : "open";
  if (!r.ownershipFiltered) return r.ownershipReadable === false ? "unknown" : "unscoped";
  return "scoped";
}

export type MapNode = {
  id: string;
  kind: "route" | "table" | "provider" | "helper" | "control";
  label: string;
  p: [number, number, number];
  detail: string;
  file?: string;
  finding?: MapFinding["severity"];
  hot?: boolean;
  connection?: "available" | "coming_soon";
  /** Route nodes carry their facts so the map can simulate a request. */
  fact?: MapRoute;
  exposure?: Exposure;
};
export type RouteMap = { nodes: MapNode[]; edges: MapEdge[]; truncated: boolean };

const CONTROLS = {
  session: { label: "Sign-in check", detail: (n: number) => `A sign-in check read on ${n} route${n === 1 ? "" : "s"}.` },
  scope: { label: "Rows scoped to the caller", detail: (n: number) => `Queries narrowed to the caller's own rows on ${n} route${n === 1 ? "" : "s"}.` },
  secret: { label: "Secret or signature", detail: (n: number) => `A secret or signature required on ${n} route${n === 1 ? "" : "s"}.` },
} as const;
const RISK_RANK: Record<Risk, number> = { open: 0, unknown: 1, unscoped: 2, guarded: 3 };

const MAX_ROUTES = 120;
const MAX_HELPERS = 30;
const MAX_STORED = 400;

const storedRoute = z.object({
  path: z.string().max(1024), file: z.string().max(1024), tables: z.array(z.string().max(256)).max(40),
  authenticated: z.boolean(), ownershipFiltered: z.boolean(), machineGated: z.boolean(),
  via: z.array(z.string().max(1024)).max(12).optional(),
  identityReadable: z.boolean().optional(), ownershipReadable: z.boolean().optional(), machineGateReadable: z.boolean().optional(),
});
/** Stored route facts, validated on read; anything malformed is no facts. */
export function parseRouteFacts(value: unknown): MapRoute[] | null {
  const parsed = z.array(storedRoute).max(400).safeParse(value);
  return parsed.success && parsed.data.length > 0 ? parsed.data : null;
}

/** What an audit keeps for the map (migration 096): facts only, no source. */
export function compactRouteFacts(routes: MapRoute[]): MapRoute[] {
  return routes.slice(0, MAX_STORED).map((r) => ({
    path: r.path, file: r.file, tables: r.tables.slice(0, 40), authenticated: r.authenticated, ownershipFiltered: r.ownershipFiltered,
    machineGated: r.machineGated, via: (r.via ?? []).slice(0, 12), identityReadable: r.identityReadable ?? true,
    ownershipReadable: r.ownershipReadable ?? true, machineGateReadable: r.machineGateReadable ?? true,
  }));
}
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
    nodes.push({ id: `route:${r.path}`, kind: "route", label: r.path, p: routeSpots[i], file: r.file, fact: r, exposure: exposureOf(r),
      detail: finding ? `${finding.title}. ${controls}` : controls,
      ...(finding ? { finding: finding.severity } : {}), ...(hot.has(r.file) ? { hot: true } : {}) });
  });
  const tableSpots = spiral(tables.length, 120 + tables.length * 3, 40, 14);
  tables.forEach((t, i) => {
    const readers = routes.filter((r) => r.tables.includes(t)).length;
    nodes.push({ id: `table:${t}`, kind: "table", label: t, p: tableSpots[i], detail: `Reached by ${readers} route${readers === 1 ? "" : "s"}.` });
  });
  const providerSpots = spiral(providers.length, 220, 230, 0);
  providers.forEach((t, i) => {
    const connection = LIVE.has(t.id) ? "available" : "coming_soon";
    nodes.push({ id: `provider:${t.id}`, kind: "provider", label: t.name, p: providerSpots[i], connection,
      detail: connection === "available" ? "Inferred from your code. A read-only live connection is available." : "Inferred from your code. Live connection coming soon." });
  });

  // Shared code: a file two or more routes execute becomes a node, so routes
  // connect to each other through the helpers they share (the Obsidian view).
  const usage = new Map<string, number>();
  for (const r of routes) for (const f of new Set(r.via ?? [])) if (f !== r.file) usage.set(f, (usage.get(f) ?? 0) + 1);
  const helpers = [...usage].filter(([, n]) => n >= 2).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, MAX_HELPERS);
  const helperSet = new Set(helpers.map(([f]) => f));
  const helperSpots = spiral(helpers.length, 90 + helpers.length * 4, -40, 10);
  helpers.forEach(([f, n], i) => {
    nodes.push({ id: `helper:${f}`, kind: "helper", label: f, p: helperSpots[i], file: f,
      detail: `Shared code executed by ${n} routes. A change here changes all of them.` });
  });

  // Data flow: each route passes the controls the audit read on it, in order,
  // before reaching its tables. A flow's risk is what reaches the table.
  const edgeMap = new Map<string, MapEdge>();
  const add = (e: MapEdge) => {
    const key = `${e.from}>${e.to}>${e.kind}`;
    const prior = edgeMap.get(key);
    if (!prior || (e.risk && prior.risk && RISK_RANK[e.risk] < RISK_RANK[prior.risk])) edgeMap.set(key, e);
  };
  const controlUse = { session: 0, scope: 0, secret: 0 };
  for (const r of routes) {
    for (const f of new Set(r.via ?? [])) if (helperSet.has(f)) add({ from: `route:${r.path}`, to: `helper:${f}`, kind: "shared" });
    const reached = r.tables.filter((t) => tableSet.has(t));
    if (reached.length === 0) continue;
    const from = `route:${r.path}`;
    const exposure = exposureOf(r);
    const flow = (src: string, risk: Risk) => { for (const t of reached) add({ from: src, to: `table:${t}`, kind: "flow", risk }); };
    if (exposure === "secret") {
      controlUse.secret++; add({ from, to: "control:secret", kind: "guard" }); flow("control:secret", "guarded");
    } else if (r.authenticated && r.identityReadable !== false) {
      controlUse.session++; add({ from, to: "control:session", kind: "guard" });
      if (exposure === "scoped") {
        controlUse.scope++; add({ from: "control:session", to: "control:scope", kind: "guard" }); flow("control:scope", "guarded");
      } else flow("control:session", exposure === "unknown" ? "unknown" : "unscoped");
    } else flow(from, exposure === "unknown" ? "unknown" : "open");
  }
  const controlSpots: [number, number, number][] = [[-170, -20, 60], [170, -20, 60], [0, -20, -180]];
  (Object.keys(CONTROLS) as (keyof typeof CONTROLS)[]).forEach((key, i) => {
    if (controlUse[key] === 0) return;
    nodes.push({ id: `control:${key}`, kind: "control", label: CONTROLS[key].label, p: controlSpots[i], detail: CONTROLS[key].detail(controlUse[key]) });
  });
  if (database) for (const t of tables) add({ from: `table:${t}`, to: `provider:${database.id}`, kind: "store" });
  const edges = [...edgeMap.values()];
  relax(nodes, edges);
  return { nodes, edges, truncated: input.routes.length > routes.length || tableSet.size < new Set(routes.flatMap((r) => r.tables)).size };
}

const LAYER_Y = { route: -150, helper: -95, control: -30, table: 70, provider: 230 } as const;
const FIT_RADIUS = 240;

/**
 * A small deterministic force layout, so routes that share tables sit
 * together (the Obsidian look) instead of a hairball. Starts from the spiral,
 * fixed iteration count, no randomness; then scaled to a fixed radius so the
 * stage can fit any repository.
 */
function relax(nodes: MapNode[], edges: MapEdge[]): void {
  const index = new Map(nodes.map((n, i) => [n.id, i]));
  const pos = nodes.map((n) => [...n.p] as [number, number, number]);
  const links = edges.map((e) => [index.get(e.from)!, index.get(e.to)!] as const);
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
      // Controls and providers hold their layer firmly so the flow reads top to bottom.
      const hold = nodes[i].kind === "control" || nodes[i].kind === "provider" ? 0.2 : 0.05;
      force[i][1] += (LAYER_Y[nodes[i].kind] - pos[i][1]) * hold;
      force[i][0] -= pos[i][0] * 0.004; force[i][2] -= pos[i][2] * 0.004;
      // Controls are pinned: they are the gates every flow passes through.
      if (nodes[i].kind === "control") continue;
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


export type Attacker = "anonymous" | "signed_in";
export type Simulation = { outcome: "stopped" | "scoped" | "reaches" | "unknown"; reached: string[]; steps: string[] };

/**
 * "What happens if someone calls this route?", told only from the facts the
 * audit read. Not traffic and not a proof: an unread control is "unknown",
 * never "stopped".
 */
export function simulateRequest(route: MapRoute, attacker: Attacker): Simulation {
  const who = attacker === "anonymous" ? "A request with no sign-in" : "A request from any signed-in user";
  const steps = [`${who} reaches ${route.path}.`];
  for (const f of route.via ?? []) steps.push(`It runs ${f}.`);
  const unknown = (what: string): Simulation => ({ outcome: "unknown", reached: [], steps: [...steps, `We could not read ${what}, so the outcome is unknown.`] });
  if (route.machineGated) {
    if (route.machineGateReadable === false) return unknown("its secret or signature check");
    return { outcome: "stopped", reached: [], steps: [...steps, "It is stopped without the secret or signature the route checks."] };
  }
  if (route.tables.length === 0) return { outcome: "stopped", reached: [], steps: [...steps, "It reaches no table we read."] };
  if (attacker === "anonymous") {
    if (route.identityReadable === false) return unknown("how it checks the caller");
    if (route.authenticated) return { outcome: "stopped", reached: [], steps: [...steps, "It is stopped by the sign-in check we read."] };
    return { outcome: "reaches", reached: route.tables, steps: [...steps, `No sign-in check was read. It reaches ${route.tables.join(", ")}.`] };
  }
  if (route.ownershipReadable === false) return unknown("how it narrows rows to the caller");
  if (route.ownershipFiltered) return { outcome: "scoped", reached: route.tables, steps: [...steps, `It reaches ${route.tables.join(", ")}, narrowed to the caller's own rows.`] };
  return { outcome: "reaches", reached: route.tables, steps: [...steps, `Nothing narrows the query to the caller. It reaches every row of ${route.tables.join(", ")}.`] };
}

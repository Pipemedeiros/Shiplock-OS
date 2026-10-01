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
export type MapLane = { label: string; p: [number, number, number] };
export type MapGroup = { exposure: Exposure; count: number; p: [number, number, number] };
export type RouteMap = { nodes: MapNode[]; edges: MapEdge[]; truncated: boolean; lanes: MapLane[]; groups: MapGroup[] };

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
  routes.forEach((r) => {
    const finding = worst.get(r.path);
    const controls = r.machineGated ? "Requires a secret or signature." : [
      r.authenticated ? "Requires a signed-in caller." : "No sign-in check read.",
      r.tables.length ? (r.ownershipFiltered ? "Scoped to the caller's rows." : "Not scoped to the caller's rows.") : "Reaches no table we read.",
    ].join(" ");
    nodes.push({ id: `route:${r.path}`, kind: "route", label: r.path, p: [0, 0, 0], file: r.file, fact: r, exposure: exposureOf(r),
      detail: finding ? `${finding.title}. ${controls}` : controls,
      ...(finding ? { finding: finding.severity } : {}), ...(hot.has(r.file) ? { hot: true } : {}) });
  });
  tables.forEach((t) => {
    const readers = routes.filter((r) => r.tables.includes(t)).length;
    nodes.push({ id: `table:${t}`, kind: "table", label: t, p: [0, 0, 0], detail: `Reached by ${readers} route${readers === 1 ? "" : "s"}.` });
  });
  providers.forEach((t) => {
    const connection = LIVE.has(t.id) ? "available" : "coming_soon";
    nodes.push({ id: `provider:${t.id}`, kind: "provider", label: t.name, p: [0, 0, 0], connection,
      detail: connection === "available" ? "Inferred from your code. A read-only live connection is available." : "Inferred from your code. Live connection coming soon." });
  });

  // Shared code: a file two or more routes execute becomes a node, so routes
  // connect to each other through the helpers they share (the Obsidian view).
  const usage = new Map<string, number>();
  for (const r of routes) for (const f of new Set(r.via ?? [])) if (f !== r.file) usage.set(f, (usage.get(f) ?? 0) + 1);
  const helpers = [...usage].filter(([, n]) => n >= 2).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, MAX_HELPERS);
  const helperSet = new Set(helpers.map(([f]) => f));
  helpers.forEach(([f, n]) => {
    nodes.push({ id: `helper:${f}`, kind: "helper", label: f, p: [0, 0, 0], file: f,
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
  (Object.keys(CONTROLS) as (keyof typeof CONTROLS)[]).forEach((key) => {
    if (controlUse[key] === 0) return;
    nodes.push({ id: `control:${key}`, kind: "control", label: CONTROLS[key].label, p: [0, 0, 0], detail: CONTROLS[key].detail(controlUse[key]) });
  });
  if (database) for (const t of tables) add({ from: `table:${t}`, to: `provider:${database.id}`, kind: "store" });
  const edges = [...edgeMap.values()];
  const { lanes, groups } = layoutLanes(nodes, edges, database?.id);
  return { nodes, edges, lanes, groups, truncated: input.routes.length > routes.length || tableSet.size < new Set(routes.flatMap((r) => r.tables)).size };
}

const LANES = [
  { kind: "route", label: "Ways in", x: -340 },
  { kind: "helper", label: "Shared code", x: -150 },
  { kind: "control", label: "Checks", x: -40 },
  { kind: "table", label: "Your data", x: 100 },
  { kind: "provider", label: "Services", x: 260 },
] as const;
const EXPOSURE_ORDER: Exposure[] = ["open", "unknown", "unscoped", "scoped", "secret", "none"];
const LANE_HEIGHT = 420;
const ROWS_MAX = 16;

/**
 * Organized lanes, read left to right: ways in, shared code, checks, your
 * data, services (Felipe 2026-10-01: organized, concise, easy to read). Routes
 * are grouped by exposure, worst first; tables by the worst flow reaching
 * them. A long lane folds into columns stacked in depth, so a large app reads
 * as a slab instead of a hairball. Deterministic: no randomness, no physics.
 */
function layoutLanes(nodes: MapNode[], edges: MapEdge[], databaseId?: string): { lanes: MapLane[]; groups: MapGroup[] } {
  const worstIn = new Map<string, number>();
  for (const e of edges) if (e.kind === "flow") worstIn.set(e.to, Math.min(worstIn.get(e.to) ?? 9, RISK_RANK[e.risk ?? "guarded"]));
  const readers = new Map<string, number>();
  for (const e of edges) if (e.kind === "flow" || e.kind === "shared") readers.set(e.to, (readers.get(e.to) ?? 0) + 1);
  const sev = (n: MapNode) => (n.finding ? rank[n.finding] : 3);
  const order: Record<MapNode["kind"], (a: MapNode, b: MapNode) => number> = {
    route: (a, b) => EXPOSURE_ORDER.indexOf(a.exposure ?? "none") - EXPOSURE_ORDER.indexOf(b.exposure ?? "none") || sev(a) - sev(b) || a.label.localeCompare(b.label),
    helper: (a, b) => (readers.get(b.id) ?? 0) - (readers.get(a.id) ?? 0) || a.label.localeCompare(b.label),
    control: (a, b) => ["control:session", "control:scope", "control:secret"].indexOf(a.id) - ["control:session", "control:scope", "control:secret"].indexOf(b.id),
    table: (a, b) => (worstIn.get(a.id) ?? 9) - (worstIn.get(b.id) ?? 9) || (readers.get(b.id) ?? 0) - (readers.get(a.id) ?? 0) || a.label.localeCompare(b.label),
    provider: (a, b) => Number(b.id === `provider:${databaseId}`) - Number(a.id === `provider:${databaseId}`) || a.label.localeCompare(b.label),
  };
  const lanes: MapLane[] = [];
  const groups: MapGroup[] = [];
  for (const lane of LANES) {
    const items = nodes.filter((n) => n.kind === lane.kind).sort(order[lane.kind]);
    if (items.length === 0) continue;
    if (lane.kind === "route") {
      // Each exposure group is its own block, worst first, filled in short
      // rows: a glance shows how many ways in sit in each group.
      const bands = EXPOSURE_ORDER.map((exposure) => items.filter((n) => n.exposure === exposure)).filter((b) => b.length > 0);
      const perRow = Math.min(8, Math.max(3, Math.ceil(Math.sqrt(items.length / bands.length) * 1.4)));
      const rowGap = 17, bandGap = 30;
      const height = bands.reduce((h, b) => h + Math.ceil(b.length / perRow) * rowGap, 0) + (bands.length - 1) * bandGap;
      let y = -height / 2;
      for (const band of bands) {
        groups.push({ exposure: band[0].exposure ?? "none", count: band.length, p: [lane.x - 8, Math.round(y - 15), 0] });
        band.forEach((n, i) => { n.p = [Math.round(lane.x + (i % perRow) * 17), Math.round(y + Math.floor(i / perRow) * rowGap), 0]; });
        y += Math.ceil(band.length / perRow) * rowGap + bandGap;
      }
      lanes.push({ label: lane.label, p: [lane.x + ((perRow - 1) * 17) / 2, Math.round(-height / 2 - 38), 0] });
      continue;
    }
    const columns = Math.max(1, Math.ceil(items.length / ROWS_MAX));
    const rows = Math.ceil(items.length / columns);
    const gap = lane.kind === "control" ? 90 : Math.min(30, LANE_HEIGHT / Math.max(1, rows));
    const top = -((rows - 1) * gap) / 2;
    items.forEach((n, i) => {
      const col = Math.floor(i / rows), row = i % rows;
      // A long lane folds into columns stepped back in depth: a stacked slab.
      n.p = [Math.round(lane.x + col * 16), Math.round(top + row * gap), Math.round(-col * 46 + (columns - 1) * 23)];
    });
    lanes.push({ label: lane.label, p: [lane.x, Math.round(top - 34), 0] });
  }
  return { lanes, groups };
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

export interface LabelBox { id: string; x: number; y: number; w: number; h: number; priority: number; force?: boolean }

/** Greedy label placement: forced labels (the picked node, the simulated
 * path) always show; others show in priority order unless they would cover a
 * label already placed. */
export function placeLabels(boxes: LabelBox[]): Set<string> {
  const placed: LabelBox[] = [];
  const hit = (a: LabelBox, b: LabelBox) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
  const order = [...boxes].sort((a, b) => Number(!!b.force) - Number(!!a.force) || b.priority - a.priority);
  for (const box of order) if (box.force || !placed.some((p) => hit(p, box))) placed.push(box);
  return new Set(placed.map((p) => p.id));
}

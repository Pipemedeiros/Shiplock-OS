import type { RouteFact } from "./routeInventory";
import type { SupabaseAuthConfig } from "@/lib/deep/supabaseMgmt";
import { normaliseLintName, type PgPolicy, type SupabaseAdvisor } from "@/lib/deep/policyScan";

// The asset graph (PRODUCT-DESIGN.md §5.2). Collectors produce facts; this
// assembles them into nodes and edges so the reasoner can walk them.
//
// The graph is the product. Supabase sees the database, a pentest agent sees the
// code, an edge proxy sees the traffic — and the risks that actually kill a small
// SaaS live in the intersection none of them can see. A permissive policy is a
// lint. A permissive policy on a table your public API reads without an
// ownership check, on a project where anyone can self-register, is an incident
// waiting for someone to notice.
//
// Everything here is PURE and synchronous. Fetching belongs to the collectors;
// this module must stay trivially testable, because a reasoner that silently
// mis-assembles its inputs produces confident nonsense.

export type NodeKind = "table" | "route" | "policy" | "config" | "bucket";

export interface GraphNode {
  id: string; // "table:public.invoices", "route:/api/invoices"
  kind: NodeKind;
  name: string;
  /** Collector-supplied attributes. Facts only — no judgements. */
  attrs: Record<string, unknown>;
}

export type EdgeKind = "exposes" | "governs" | "permits";

export interface GraphEdge {
  from: string;
  to: string;
  kind: EdgeKind;
}

export interface AssetGraph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
}

// ── Table facts, assembled from several collectors ─────────────────────────

export interface TableFacts {
  schema: string;
  name: string;
  qualified: string;
  /** RLS switched on. `null` when no collector told us — unknown, not false. */
  rlsEnabled: boolean | null;
  /** A policy that grants access unconditionally (USING (true) / advisor 0024). */
  permissivePolicy: boolean;
  /** Roles any permissive policy applies to, e.g. anon / authenticated. */
  permissiveRoles: string[];
  /** Looks like it holds personal or financial data (used for ranking only). */
  sensitive: boolean;
}

/**
 * Tables whose contents would matter if they leaked. Ranking input ONLY — never
 * the reason a finding exists, and never suppresses one. A table we don't
 * recognise is still reported; it just doesn't get the sensitivity bump.
 *
 * This is the cheap version of the PII inventory (A21). It is deliberately a
 * name heuristic and is documented as such, because guessing wrong here changes
 * an ordering, not a verdict.
 */
const SENSITIVE_TABLE_RE =
  /\b(user|users|profile|profiles|account|accounts|customer|customers|member|members|invoice|invoices|payment|payments|charge|charges|subscription|subscriptions|order|orders|transaction|transactions|card|cards|billing|message|messages|chat|chats|email|emails|address|addresses|phone|patient|patients|medical|health|document|documents|file|files|note|notes|session|sessions|token|tokens|credential|credentials|secret|secrets|api_keys?|apikeys?|phones?|ssns?)\b/i;

export function isSensitiveTableName(name: string): boolean {
  return SENSITIVE_TABLE_RE.test(name.replace(/^[\w]+\./, ""));
}

/** `USING (true)` and equivalents — a policy that filters nothing. */
export function isPermissiveExpression(expr: string | null | undefined): boolean {
  if (!expr) return false;
  const normalised = expr.trim().toLowerCase().replace(/\s+/g, " ").replace(/^\(+|\)+$/g, "");
  return normalised === "true" || normalised === "1=1" || normalised === "(true)";
}

export interface GraphInput {
  routes?: RouteFact[];
  policies?: PgPolicy[];
  advisors?: SupabaseAdvisor[];
  authConfig?: SupabaseAuthConfig | null;
  /** Tables with RLS state, from the 16-check scan. */
  scanTables?: { name: string; rlsEnabled: boolean }[];
  /** Paths currently under attack, from the traffic collector. */
  trafficHotPaths?: { path: string; suspiciousRequests: number }[];
}

export interface AuthPosture {
  /** Anyone can create an account without an invite. `null` when unknown. */
  signupsOpen: boolean | null;
  /** Email confirmation not required, so a fake address gets a session. */
  autoConfirm: boolean | null;
}

/**
 * Signup posture from the auth config.
 *
 * `disable_signup: false` means signups are OPEN — the double negative is easy
 * to read backwards, and reading it backwards would invert the most important
 * amplifier in the whole reasoner, so it is isolated here and tested directly.
 */
export function readAuthPosture(config: SupabaseAuthConfig | null | undefined): AuthPosture {
  if (!config) return { signupsOpen: null, autoConfirm: null };
  const disable = config["disable_signup"];
  const autoconfirm = config["mailer_autoconfirm"];
  return {
    signupsOpen: typeof disable === "boolean" ? !disable : null,
    autoConfirm: typeof autoconfirm === "boolean" ? autoconfirm : null,
  };
}

/** Advisor lints that assert a table has RLS off entirely. */
const RLS_DISABLED_LINTS = new Set(["rls_disabled_in_public", "policy_exists_rls_disabled"]);
/** Advisor lints that assert a policy grants unconditional access. */
const PERMISSIVE_LINTS = new Set(["rls_policy_always_true"]);

export function buildTableFacts(input: GraphInput): Map<string, TableFacts> {
  const tables = new Map<string, TableFacts>();

  const ensure = (schema: string, name: string): TableFacts => {
    const qualified = `${schema}.${name}`;
    let t = tables.get(qualified);
    if (!t) {
      t = {
        schema,
        name,
        qualified,
        rlsEnabled: null,
        permissivePolicy: false,
        permissiveRoles: [],
        sensitive: isSensitiveTableName(name),
      };
      tables.set(qualified, t);
    }
    return t;
  };

  // The 16-check scan is the authoritative source for RLS on/off.
  for (const t of input.scanTables ?? []) {
    ensure("public", t.name).rlsEnabled = t.rlsEnabled;
  }

  // Our own policy detector: a policy whose USING expression filters nothing.
  for (const p of input.policies ?? []) {
    const t = ensure(p.schemaname ?? "public", p.tablename);
    if (isPermissiveExpression(p.qual)) {
      t.permissivePolicy = true;
      for (const role of p.roles ?? []) {
        if (!t.permissiveRoles.includes(role)) t.permissiveRoles.push(role);
      }
    }
  }

  // Supabase's advisors, as a second independent source for the same facts.
  for (const a of input.advisors ?? []) {
    if (!a.name) continue;
    const lint = normaliseLintName(a.name);
    const name = a.metadata?.name;
    if (!name) continue;
    const t = ensure(a.metadata?.schema ?? "public", name);
    if (RLS_DISABLED_LINTS.has(lint)) t.rlsEnabled = false;
    if (PERMISSIVE_LINTS.has(lint)) t.permissivePolicy = true;
  }

  return tables;
}

export function buildGraph(input: GraphInput): AssetGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const tableFacts = buildTableFacts(input);
  for (const t of tableFacts.values()) {
    nodes.set(`table:${t.qualified}`, {
      id: `table:${t.qualified}`,
      kind: "table",
      name: t.qualified,
      attrs: { ...t },
    });
  }

  const posture = readAuthPosture(input.authConfig);
  nodes.set("config:auth", {
    id: "config:auth",
    kind: "config",
    name: "Supabase Auth configuration",
    attrs: { ...posture },
  });

  const hot = new Map((input.trafficHotPaths ?? []).map((h) => [h.path, h.suspiciousRequests]));

  for (const route of input.routes ?? []) {
    const id = `route:${route.path}`;
    nodes.set(id, {
      id,
      kind: "route",
      name: route.path,
      attrs: { ...route, suspiciousRequests: hot.get(route.path) ?? 0 },
    });

    for (const table of route.tables) {
      if (table.startsWith("rpc:")) continue; // a function call, not a table read
      const qualified = table.includes(".") ? table : `public.${table}`;
      const tableId = `table:${qualified}`;
      // A route may reference a table no other collector saw — record it, so the
      // graph never silently drops an edge just because the DB collector didn't
      // run (an unconnected Supabase project is a normal state).
      if (!nodes.has(tableId)) {
        const [schema, name] = qualified.split(".");
        nodes.set(tableId, {
          id: tableId,
          kind: "table",
          name: qualified,
          attrs: {
            schema,
            name,
            qualified,
            rlsEnabled: null,
            permissivePolicy: false,
            permissiveRoles: [],
            sensitive: isSensitiveTableName(name),
          } satisfies TableFacts,
        });
      }
      edges.push({ from: id, to: tableId, kind: "exposes" });
    }
  }

  return { nodes, edges };
}

/** Every table a given route reaches. */
export function tablesForRoute(graph: AssetGraph, routeId: string): GraphNode[] {
  return graph.edges
    .filter((e) => e.from === routeId && e.kind === "exposes")
    .map((e) => graph.nodes.get(e.to))
    .filter((n): n is GraphNode => n !== undefined);
}

/** Every route that reaches a given table. */
export function routesForTable(graph: AssetGraph, tableId: string): GraphNode[] {
  return graph.edges
    .filter((e) => e.to === tableId && e.kind === "exposes")
    .map((e) => graph.nodes.get(e.from))
    .filter((n): n is GraphNode => n !== undefined);
}

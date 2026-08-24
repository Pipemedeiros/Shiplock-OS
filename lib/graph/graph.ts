import type { RouteFact } from "./routeInventory";
import type { SupabaseAuthConfig } from "@/lib/deep/supabaseMgmt";
import { normaliseLintName, type PgPolicy, type SupabaseAdvisor } from "@/lib/deep/policyScan";
import { isProvable, vocabulary, type AuthzProvider } from "./providers";

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

// ── Authorization facts, assembled from several collectors ─────────────────

/**
 * What we know about who may read a given asset.
 *
 * These are deliberately PROVIDER-NEUTRAL nouns. The collectors speak Postgres
 * (`PgPolicy`, advisor lints, `rlsEnabled`) because they are reading Postgres;
 * by the time facts reach the reasoner they have been translated into questions
 * every authorization engine can answer. That translation happens here, in
 * `buildAuthzFacts`, and it is the seam that decides whether supporting a second
 * store is a collector or a rewrite.
 *
 * The word "table" is avoided on purpose — Firestore has collections, and a
 * reasoner that says `table` everywhere will grow a `table ?? collection`
 * conditional the first time that matters.
 */
export interface AuthzFacts {
  schema: string;
  name: string;
  qualified: string;
  /**
   * Which engine governs this asset. `null` when no database collector ran, and
   * distinct from `app-layer`: `null` is "we did not look", `app-layer` is "we
   * looked and there is no declarative rule".
   */
  provider: AuthzProvider | null;
  /**
   * The authorization mechanism is switched on for this asset. `null` when no
   * collector told us — unknown, not false.
   */
  enforced: boolean | null;
  /** A rule that grants access unconditionally (USING (true) / advisor 0024). */
  unconditionalGrant: boolean;
  /**
   * Whether the access RULES themselves were successfully enumerated.
   *
   * This is the difference between "we read every policy on this table and none
   * of them filters nothing" and "we never got to look". Both leave
   * `unconditionalGrant` false, and treating them the same is how a table with
   * RLS switched on and a `USING (true)` policy on it reported as protected: the
   * enforcement flag was observed, the rule was not, and the missing half was
   * read as good news.
   *
   * A customer running only the anon-key scan is the ordinary case here — that
   * scan can see THAT row security is on, never WHAT the policies say. So this
   * is false far more often than it is a failure, which is exactly why it has to
   * be modelled rather than assumed.
   */
  rulesRead: boolean;
  /** Principals any unconditional grant applies to, e.g. anon / authenticated. */
  grantedRoles: string[];
  /**
   * Whether a leak here could be REPRODUCED in the proving ground rather than
   * inferred. A capability, not a result — see the note in `providers.ts`.
   */
  provable: boolean;
  /** Looks like it holds personal or financial data (used for ranking only). */
  sensitive: boolean;
}

/**
 * The previous name for {@link AuthzFacts}, kept so existing imports keep
 * compiling. New code should use `AuthzFacts`; this alias will go once the last
 * caller has moved.
 *
 * @deprecated Use {@link AuthzFacts}.
 */
export type TableFacts = AuthzFacts;

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
  /**
   * Which authorization engine these facts describe. Optional: today every
   * collector that fills this input reads Postgres, so it is inferred when
   * absent. A collector for a different store sets it explicitly rather than
   * relying on that inference.
   */
  authzProvider?: AuthzProvider;
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

/**
 * Which authorization engine this input describes.
 *
 * Explicit when a collector said so. Otherwise inferred as Postgres — but only
 * when a database collector actually reported something, so an input with no
 * database half stays honestly `null` instead of claiming a provider we never
 * observed. That distinction is load-bearing downstream: `null` suppresses the
 * paths that need a database fact, where a wrong guess would invent one.
 */
export function observedProvider(input: GraphInput): AuthzProvider | null {
  if (input.authzProvider) return input.authzProvider;
  const observed =
    (input.scanTables?.length ?? 0) > 0 ||
    (input.policies?.length ?? 0) > 0 ||
    (input.advisors?.length ?? 0) > 0;
  return observed ? "postgres-rls" : null;
}

/**
 * Translate collector output into provider-neutral authorization facts.
 *
 * Every input here is Postgres-shaped, and that is correct — these collectors
 * read Postgres. The `provider` stamp is what lets a future Firestore collector
 * write into the same map without any downstream code learning a second
 * vocabulary.
 */
export function buildAuthzFacts(input: GraphInput): Map<string, AuthzFacts> {
  // Which engine the facts in this input came from. Explicit when a collector
  // said so, otherwise inferred from the fact that these collectors are Postgres
  // ones — but only when at least one of them actually reported something, so an
  // empty input stays honestly `null` rather than claiming a provider we never saw.
  const provider = observedProvider(input);
  // `undefined` means no rule collector ran; `[]` means one ran and found none.
  // The distinction is the whole point of this flag, so it is read from the
  // presence of the key rather than from its length.
  //
  // Advisors count as a rule witness alongside policies: an advisor run that
  // reports no `rls_policy_always_true` is genuine evidence that no policy
  // grants access unconditionally, arrived at independently. Either source
  // having run is enough to say we looked.
  const rulesRead = input.policies !== undefined || input.advisors !== undefined;

  const assets = new Map<string, AuthzFacts>();

  const ensure = (schema: string, name: string): AuthzFacts => {
    const qualified = `${schema}.${name}`;
    let t = assets.get(qualified);
    if (!t) {
      t = {
        schema,
        name,
        qualified,
        provider,
        enforced: null,
        unconditionalGrant: false,
        rulesRead,
        grantedRoles: [],
        provable: isProvable(provider),
        sensitive: isSensitiveTableName(name),
      };
      assets.set(qualified, t);
    }
    return t;
  };

  // The 16-check scan is the authoritative source for whether RLS is on.
  for (const t of input.scanTables ?? []) {
    ensure("public", t.name).enforced = t.rlsEnabled;
  }

  // Our own policy detector: a policy whose USING expression filters nothing.
  for (const p of input.policies ?? []) {
    const t = ensure(p.schemaname ?? "public", p.tablename);
    if (isPermissiveExpression(p.qual)) {
      t.unconditionalGrant = true;
      for (const role of p.roles ?? []) {
        if (!t.grantedRoles.includes(role)) t.grantedRoles.push(role);
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
    if (RLS_DISABLED_LINTS.has(lint)) t.enforced = false;
    if (PERMISSIVE_LINTS.has(lint)) t.unconditionalGrant = true;
  }

  return assets;
}

/**
 * @deprecated Use {@link buildAuthzFacts}.
 */
export const buildTableFacts = buildAuthzFacts;

export function buildGraph(input: GraphInput): AssetGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const authzFacts = buildAuthzFacts(input);
  for (const t of authzFacts.values()) {
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
    // Named by the provider, not hardcoded: this string reaches customer-facing
    // evidence, and a Firestore customer reading "Supabase Auth configuration"
    // would rightly stop trusting the rest of the finding.
    name: vocabulary(input.authzProvider).configLabel,
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
            // The route collector saw this asset; no database collector did. So
            // the provider is whatever the database half reported overall, and
            // `enforced` stays null — unknown, never assumed unprotected.
            provider: observedProvider(input),
            enforced: null,
            unconditionalGrant: false,
            // No rule collector reported on this asset specifically, but the
            // flag tracks whether the RUN happened, not whether this table
            // appeared in it — a table absent from a successful policy read
            // genuinely has no policies.
            rulesRead: input.policies !== undefined || input.advisors !== undefined,
            grantedRoles: [],
            provable: isProvable(observedProvider(input)),
            sensitive: isSensitiveTableName(name),
          } satisfies AuthzFacts,
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

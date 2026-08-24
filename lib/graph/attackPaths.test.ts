import { describe, expect, it } from "vitest";
import { findAttackPaths } from "./attackPaths";
import { collectRoutes } from "./routeInventory";
import {
  buildGraph,
  buildAuthzFacts,
  isPermissiveExpression,
  isSensitiveTableName,
  readAuthPosture,
  routesForTable,
  tablesForRoute,
} from "./graph";

const routeFile = (path: string, content: string) => ({ path, content });

const anonReadsInvoices = collectRoutes([
  routeFile("app/api/invoices/route.ts", `export async function GET(){ return supabase.from("invoices").select("*") }`),
]);

const authedUnscoped = collectRoutes([
  routeFile(
    "app/api/invoices/route.ts",
    `export async function GET(){ const { data:{ user } } = await supabase.auth.getUser(); return supabase.from("invoices").select("*") }`
  ),
]);

const authedScoped = collectRoutes([
  routeFile(
    "app/api/invoices/route.ts",
    `export async function GET(){ const { data:{ user } } = await supabase.auth.getUser(); return supabase.from("invoices").select("*").eq("user_id", user.id) }`
  ),
]);

describe("graph primitives", () => {
  it("recognises expressions that filter nothing", () => {
    for (const e of ["true", "TRUE", " true ", "(true)", "1=1"]) {
      expect(isPermissiveExpression(e), e).toBe(true);
    }
  });

  it("does not treat a real predicate as permissive", () => {
    for (const e of ["auth.uid() = user_id", "status = 'paid'", null, undefined, ""]) {
      expect(isPermissiveExpression(e as string), String(e)).toBe(false);
    }
  });

  it("identifies tables that would matter if they leaked", () => {
    for (const n of ["invoices", "users", "payments", "messages", "api_keys"]) {
      expect(isSensitiveTableName(n), n).toBe(true);
    }
    expect(isSensitiveTableName("feature_flags")).toBe(false);
  });

  // disable_signup is a double negative and inverting it would flip the most
  // important amplifier in the reasoner.
  it("reads signup posture without inverting it", () => {
    expect(readAuthPosture({ disable_signup: false }).signupsOpen).toBe(true);
    expect(readAuthPosture({ disable_signup: true }).signupsOpen).toBe(false);
  });

  it("treats a missing signup setting as UNKNOWN, not open", () => {
    expect(readAuthPosture({}).signupsOpen).toBeNull();
    expect(readAuthPosture(null).signupsOpen).toBeNull();
  });

  it("merges RLS facts from the scan and the advisors", () => {
    const tables = buildAuthzFacts({
      scanTables: [{ name: "orders", rlsEnabled: true }],
      advisors: [{ name: "0013_rls_disabled_in_public", level: "ERROR", metadata: { schema: "public", name: "leaky" } }],
      policies: [
        { schemaname: "public", tablename: "invoices", policyname: "p", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] },
      ],
    });
    expect(tables.get("public.orders")?.enforced).toBe(true);
    expect(tables.get("public.leaky")?.enforced).toBe(false);
    expect(tables.get("public.invoices")?.unconditionalGrant).toBe(true);
    expect(tables.get("public.invoices")?.grantedRoles).toEqual(["anon"]);
  });

  it("stamps Postgres facts with a provider, and marks them provable", () => {
    const tables = buildAuthzFacts({ scanTables: [{ name: "orders", rlsEnabled: false }] });
    expect(tables.get("public.orders")?.provider).toBe("postgres-rls");
    expect(tables.get("public.orders")?.provable).toBe(true);
  });

  it("does not claim a provider when no database collector reported", () => {
    // Route facts alone must not imply a store we never looked at. `null` here
    // is what keeps `enforced: null` meaning "we did not check" rather than
    // "Postgres, unprotected".
    const graph = buildGraph({ routes: anonReadsInvoices });
    const node = graph.nodes.get("table:public.invoices");
    expect((node?.attrs as { provider: unknown }).provider).toBeNull();
    expect((node?.attrs as { provable: unknown }).provable).toBe(false);
  });

  it("honours an explicit provider, and reports it as not yet provable", () => {
    const tables = buildAuthzFacts({
      authzProvider: "firebase-rules",
      scanTables: [{ name: "orders", rlsEnabled: false }],
    });
    expect(tables.get("public.orders")?.provider).toBe("firebase-rules");
    expect(tables.get("public.orders")?.provable).toBe(false);
  });

  it("links routes to tables in both directions", () => {
    const graph = buildGraph({ routes: anonReadsInvoices });
    expect(tablesForRoute(graph, "route:/api/invoices").map((n) => n.name)).toEqual(["public.invoices"]);
    expect(routesForTable(graph, "table:public.invoices").map((n) => n.name)).toEqual(["/api/invoices"]);
  });

  it("records a table the database collector never saw", () => {
    const graph = buildGraph({ routes: anonReadsInvoices });
    expect(graph.nodes.has("table:public.invoices")).toBe(true);
  });

  it("does not create a table node for an rpc call", () => {
    const routes = collectRoutes([routeFile("app/api/x/route.ts", `export async function POST(){ return supabase.rpc("do_thing") }`)]);
    const graph = buildGraph({ routes });
    expect([...graph.nodes.keys()].filter((k) => k.startsWith("table:"))).toEqual([]);
  });
});

describe("path 1 — anonymous reach into an unprotected table", () => {
  it("fires when a public route reads a table with RLS off", () => {
    const paths = findAttackPaths({
      routes: anonReadsInvoices,
      scanTables: [{ name: "invoices", rlsEnabled: false }],
    });
    expect(paths).toHaveLength(1);
    expect(paths[0].severity).toBe("CRITICAL");
    expect(paths[0].id).toContain("anon_read");
    expect(paths[0].surfaces).toEqual(["source", "db"]);
  });

  it("fires when the table has a policy that filters nothing", () => {
    const paths = findAttackPaths({
      routes: anonReadsInvoices,
      scanTables: [{ name: "invoices", rlsEnabled: true }],
      policies: [
        { schemaname: "public", tablename: "invoices", policyname: "p", cmd: "SELECT", qual: "true", with_check: null, roles: ["anon"] },
      ],
    });
    expect(paths[0].id).toContain("anon_read");
  });

  // Each half is unremarkable alone; that is the point of the graph.
  it("stays SILENT when the route is public but the table is protected", () => {
    expect(
      findAttackPaths({ routes: anonReadsInvoices, scanTables: [{ name: "invoices", rlsEnabled: true }] })
    ).toEqual([]);
  });

  it("stays silent when the table is unprotected but no route exposes it", () => {
    expect(findAttackPaths({ routes: [], scanTables: [{ name: "invoices", rlsEnabled: false }] })).toEqual([]);
  });

  it("stays silent for a machine-gated route", () => {
    const routes = collectRoutes([
      routeFile("app/api/cron/route.ts", `export async function GET(req){ if(req.headers.get("authorization")!==\`Bearer \${process.env.CRON_SECRET}\`) return new Response("no"); return supabase.from("invoices").select() }`),
    ]);
    expect(findAttackPaths({ routes, scanTables: [{ name: "invoices", rlsEnabled: false }] })).toEqual([]);
  });

  it("explains that fixing either half closes the path", () => {
    const paths = findAttackPaths({ routes: anonReadsInvoices, scanTables: [{ name: "invoices", rlsEnabled: false }] });
    expect(paths[0].consequence).toContain("Fix either half");
  });
});

describe("path 2 — tenant isolation (A4)", () => {
  const base = {
    routes: authedUnscoped,
    scanTables: [{ name: "invoices", rlsEnabled: true }],
    policies: [
      { schemaname: "public", tablename: "invoices", policyname: "p", cmd: "SELECT", qual: "true", with_check: null, roles: ["authenticated"] },
    ],
  };

  it("fires when an authenticated route applies no ownership filter", () => {
    const paths = findAttackPaths(base);
    expect(paths).toHaveLength(1);
    expect(paths[0].id).toContain("tenant_isolation");
    expect(paths[0].title).toContain("Any signed-in user");
  });

  // The sentence no single tool in the stack can produce.
  it("escalates to 'anyone can sign up' when signups are open", () => {
    const paths = findAttackPaths({ ...base, authConfig: { disable_signup: false } });
    expect(paths[0].title).toBe("Anyone can sign up and read every row of public.invoices");
    expect(paths[0].surfaces).toEqual(["source", "db", "config"]);
  });

  it("mentions unconfirmed addresses when auto-confirm is on", () => {
    const paths = findAttackPaths({
      ...base,
      authConfig: { disable_signup: false, mailer_autoconfirm: true },
    });
    expect(paths[0].consequence).toContain("never have to confirm");
  });

  it("does not claim open signups when the setting is unknown", () => {
    const paths = findAttackPaths(base);
    expect(paths[0].title).not.toContain("sign up");
    expect(paths[0].surfaces).not.toContain("config");
  });

  // The whole reason this check is worth having: it looks correct in review.
  it("acknowledges the route DOES authenticate, so the reader isn't confused", () => {
    expect(findAttackPaths(base)[0].consequence).toContain("does check that the caller is signed in");
  });

  it("stays SILENT when the route scopes the query to the caller", () => {
    expect(findAttackPaths({ ...base, routes: authedScoped })).toEqual([]);
  });

  it("stays silent when the table has a real policy", () => {
    expect(
      findAttackPaths({
        routes: authedUnscoped,
        scanTables: [{ name: "invoices", rlsEnabled: true }],
        policies: [
          { schemaname: "public", tablename: "invoices", policyname: "p", cmd: "SELECT", qual: "auth.uid() = user_id", with_check: null, roles: ["authenticated"] },
        ],
      })
    ).toEqual([]);
  });
});

describe("path 3 — service-role route with no ownership filter", () => {
  it("fires because RLS cannot help when it is bypassed", () => {
    const routes = collectRoutes([
      routeFile("app/api/admin/route.ts", `import { getSupabaseAdmin } from "@/lib/supabase";\nexport async function GET(){ const { data:{ user } } = await supabase.auth.getUser(); return getSupabaseAdmin().from("invoices").select("*") }`),
    ]);
    const paths = findAttackPaths({ routes, scanTables: [{ name: "invoices", rlsEnabled: true }] });
    expect(paths).toHaveLength(1);
    expect(paths[0].id).toContain("service_role_unscoped");
    expect(paths[0].consequence).toContain("ignores Row Level Security completely");
    expect(paths[0].consequence).toContain("the store will not catch a mistake here");
  });

  it("stays silent when the service-role query is scoped", () => {
    const routes = collectRoutes([
      routeFile("app/api/admin/route.ts", `import { getSupabaseAdmin } from "@/lib/supabase";\nexport async function GET(){ const { data:{ user } } = await supabase.auth.getUser(); return getSupabaseAdmin().from("invoices").select("*").eq("user_id", user.id) }`),
    ]);
    expect(findAttackPaths({ routes, scanTables: [{ name: "invoices", rlsEnabled: true }] })).toEqual([]);
  });
});

describe("unknown is never reported as unprotected", () => {
  // Reporting "RLS is off" when no database collector ran would be inventing a
  // fact we never observed — the failure mode fixed repeatedly in Phase 1.
  it("does not claim a table is unprotected when the database was never read", () => {
    const paths = findAttackPaths({ routes: authedUnscoped });
    expect(paths.filter((p) => p.id.includes("tenant_isolation"))).toEqual([]);
  });

  it("reports a public route over a sensitive table at WARNING, saying what it could not check", () => {
    const paths = findAttackPaths({ routes: anonReadsInvoices });
    expect(paths).toHaveLength(1);
    expect(paths[0].severity).toBe("WARNING");
    expect(paths[0].consequence).toContain("not been able to read them");
  });

  it("says nothing at all for a public route over a non-sensitive table with unknown RLS", () => {
    const routes = collectRoutes([
      routeFile("app/api/flags/route.ts", `export async function GET(){ return supabase.from("feature_flags").select("*") }`),
    ]);
    expect(findAttackPaths({ routes })).toEqual([]);
  });
});

describe("traffic corroboration", () => {
  const base = {
    routes: anonReadsInvoices,
    scanTables: [{ name: "invoices", rlsEnabled: false }],
  };

  it("raises urgency of an existing critical path", () => {
    const without = findAttackPaths(base);
    const withTraffic = findAttackPaths({ ...base, trafficHotPaths: [{ path: "/login", suspiciousRequests: 40 }] });
    expect(withTraffic[0].score).toBeGreaterThan(without[0].score);
    expect(withTraffic[0].surfaces).toContain("traffic");
    expect(withTraffic[0].consequence).toContain("40 suspicious requests");
  });

  // Traffic changes urgency, not truth.
  it("never invents a path from traffic alone", () => {
    expect(
      findAttackPaths({
        routes: authedScoped,
        scanTables: [{ name: "invoices", rlsEnabled: true }],
        trafficHotPaths: [{ path: "/login", suspiciousRequests: 900 }],
      })
    ).toEqual([]);
  });

  it("explicitly refuses to claim a breach", () => {
    const paths = findAttackPaths({ ...base, trafficHotPaths: [{ path: "/login", suspiciousRequests: 40 }] });
    expect(paths[0].consequence).toContain("not claiming a breach");
  });
});

describe("ranking and structure", () => {
  it("ranks a reachable path above an unreachable-but-sensitive one", () => {
    const routes = collectRoutes([
      routeFile("app/api/invoices/route.ts", `export async function GET(){ return supabase.from("invoices").select("*") }`),
      routeFile("app/api/notes/route.ts", `export async function GET(){ return supabase.from("notes").select("*") }`),
    ]);
    const paths = findAttackPaths({
      routes,
      scanTables: [{ name: "invoices", rlsEnabled: false }, { name: "notes", rlsEnabled: true }],
    });
    expect(paths[0].title).toContain("invoices");
  });

  it("every path spans at least two collectors", () => {
    const paths = findAttackPaths({
      routes: [...anonReadsInvoices, ...authedUnscoped],
      scanTables: [{ name: "invoices", rlsEnabled: false }],
      authConfig: { disable_signup: false },
      trafficHotPaths: [{ path: "/login", suspiciousRequests: 5 }],
    });
    expect(paths.length).toBeGreaterThan(0);
    for (const p of paths) expect(new Set(p.surfaces).size).toBeGreaterThanOrEqual(2);
  });

  it("gives every path evidence naming its collector", () => {
    const paths = findAttackPaths({ routes: anonReadsInvoices, scanTables: [{ name: "invoices", rlsEnabled: false }] });
    for (const p of paths) {
      expect(p.evidence.length).toBeGreaterThanOrEqual(2);
      for (const e of p.evidence) expect(["db", "source", "config", "traffic"]).toContain(e.collector);
    }
  });

  it("produces stable ids across identical runs, for the diff engine", () => {
    const input = { routes: anonReadsInvoices, scanTables: [{ name: "invoices", rlsEnabled: false }] };
    expect(findAttackPaths(input).map((p) => p.id)).toEqual(findAttackPaths(input).map((p) => p.id));
  });

  it("reports one path per route/table pair, not one per rule", () => {
    const paths = findAttackPaths({
      routes: anonReadsInvoices,
      scanTables: [{ name: "invoices", rlsEnabled: false }],
      authConfig: { disable_signup: false },
    });
    expect(paths).toHaveLength(1);
  });

  it("handles completely empty input", () => {
    expect(findAttackPaths({})).toEqual([]);
  });
});

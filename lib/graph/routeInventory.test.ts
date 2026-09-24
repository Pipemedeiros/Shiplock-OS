import { describe, expect, it } from "vitest";
import {
  analyzeRouteFile,
  collectRoutes,
  extractMethods,
  extractTables,
  isRouteFile,
  routePathFromFile,
  tablesToRoutes,
} from "./routeInventory";

const file = (path: string, content: string) => ({ path, content });

describe("routePathFromFile", () => {
  it("derives the URL from an app-router route file", () => {
    expect(routePathFromFile("app/api/scan/route.ts")).toBe("/api/scan");
  });

  it("keeps dynamic segments", () => {
    expect(routePathFromFile("app/api/monitor/vercel/[token]/route.ts")).toBe("/api/monitor/vercel/[token]");
  });

  // Route groups organise files without appearing in the URL.
  it("drops (group) segments", () => {
    expect(routePathFromFile("app/(d)/api/x/route.ts")).toBe("/api/x");
  });

  it("handles a src/ layout", () => {
    expect(routePathFromFile("src/app/api/scan/route.ts")).toBe("/api/scan");
  });

  it("handles the pages/api convention", () => {
    expect(routePathFromFile("pages/api/hello.ts")).toBe("/api/hello");
    expect(routePathFromFile("pages/api/users/index.ts")).toBe("/api/users");
    expect(routePathFromFile("pages/api/users/[id].ts")).toBe("/api/users/[id]");
  });
});

describe("isRouteFile", () => {
  it("accepts app-router route files", () => {
    expect(isRouteFile("app/api/x/route.ts")).toBe(true);
    expect(isRouteFile("src/app/api/x/route.js")).toBe(true);
  });

  it("accepts pages/api files", () => {
    expect(isRouteFile("pages/api/x.ts")).toBe(true);
  });

  // A route.ts outside app/ is not an endpoint.
  it("rejects a route.ts that isn't under app/", () => {
    expect(isRouteFile("lib/router/route.ts")).toBe(false);
  });

  it("rejects pages and components", () => {
    expect(isRouteFile("app/api/x/page.tsx")).toBe(false);
    expect(isRouteFile("components/Form.tsx")).toBe(false);
  });
});

describe("extractMethods", () => {
  it("finds exported function handlers", () => {
    expect(extractMethods("export async function GET() {}\nexport function POST() {}")).toEqual(["GET", "POST"]);
  });

  it("finds const-assigned handlers", () => {
    expect(extractMethods("export const DELETE = handler(fn);")).toEqual(["DELETE"]);
  });

  it("treats a pages/api default export as handling every method", () => {
    expect(extractMethods("export default function handler(req, res) {}")).toEqual(["ALL"]);
  });

  it("returns nothing for a file with no handler", () => {
    expect(extractMethods("const x = 1;")).toEqual([]);
  });
});

describe("extractTables", () => {
  it("finds tables from .from() calls", () => {
    expect(extractTables(`admin.from("invoices").select("*")`)).toEqual(["invoices"]);
  });

  it("dedupes and sorts", () => {
    expect(extractTables(`.from("b").from("a").from("b")`)).toEqual(["a", "b"]);
  });

  it("distinguishes an rpc call from a table read", () => {
    expect(extractTables(`.rpc("use_promo_code")`)).toEqual(["rpc:use_promo_code"]);
  });

  it("handles single and back quotes", () => {
    expect(extractTables(".from('a').from(`b`)")).toEqual(["a", "b"]);
  });

  it("returns nothing when no query is made", () => {
    expect(extractTables("return new Response('ok')")).toEqual([]);
  });

  // Step 7H: writes the corpus makes through db / tx (Drizzle) and through a
  // Prisma client that is not named `prisma` read as touching no table.
  it("reads Drizzle writes through db and a transaction", () => {
    expect(extractTables("await db.insert(monitor).values(v); await tx.update(page).set(s); await ctx.db.delete(member).where(w);"))
      .toEqual(["member", "monitor", "page"]);
  });
  it("reads Prisma calls through a transaction or a renamed client", () => {
    expect(extractTables("await tx.poll.updateMany({}); await prismaClient.booking.findUnique({}); await trx.user.delete({});"))
      .toEqual(["booking", "poll", "user"]);
  });
  it("does not read Map, store, hash or URL mutations as tables", () => {
    expect(extractTables([
      "searchParams.delete(key)", "url.searchParams.delete(name)", "store.delete(id)", "cookieStore.delete(name)",
      "hmac.update(data)", "cache.delete(key)", "map.set(k, v)", "selected.delete(item)", "db.delete", "tx.update(",
      "client.user.findMany({})",
    ].join(";\n"))).toEqual([]);
  });
});

describe("analyzeRouteFile", () => {
  it("records an authenticated, ownership-filtered read", () => {
    const fact = analyzeRouteFile(
      "app/api/invoices/route.ts",
      `export async function GET() {
         const { data: { user } } = await supabase.auth.getUser();
         return supabase.from("invoices").select("*").eq("user_id", user.id);
       }`
    );
    expect(fact.methods).toEqual(["GET"]);
    expect(fact.tables).toEqual(["invoices"]);
    expect(fact.authenticated).toBe(true);
    expect(fact.ownershipFiltered).toBe(true);
    expect(fact.usesServiceRole).toBe(false);
  });

  // The shape that matters most to the graph: reachable, unauthenticated, unscoped.
  it("records an unauthenticated, unfiltered read", () => {
    const fact = analyzeRouteFile(
      "app/api/invoices/route.ts",
      `export async function GET() { return supabase.from("invoices").select("*"); }`
    );
    expect(fact.authenticated).toBe(false);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("flags use of the service-role client, which bypasses RLS", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `import { getSupabaseAdmin } from "@/lib/supabase";
       export async function GET() { return getSupabaseAdmin().from("orders").select("*"); }`
    );
    expect(fact.usesServiceRole).toBe(true);
  });

  // A status filter is not an ownership check. Treating it as one would make the
  // reasoner call an unsafe route safe.
  it("does NOT treat a non-identity .eq() as an ownership filter", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() { return supabase.from("invoices").select("*").eq("status", "paid"); }`
    );
    expect(fact.ownershipFiltered).toBe(false);
  });

  // Regression: the ownership pattern used to prefix-match, so any filter merely
  // CONTAINING "auth"/"org"/"user" counted as an identity check — marking an
  // unscoped route safe and suppressing the tenant-isolation attack path, which
  // is the single most damaging finding this product exists to catch. Each of
  // these was a verified false positive.
  it.each([
    ['a value containing "auth"', '.eq("status", "authorized")'],
    ['a value containing "org"', '.eq("category", "organization")'],
    ['a column containing "auth"', '.eq("author_name", name)'],
    ['a value containing "account"', '.eq("plan", "account_tier")'],
    ['an unrelated org column', '.eq("org_name", "acme")'],
  ])("does NOT treat %s as an ownership filter", (_label, filter) => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() { return supabase.from("invoices").select("*")${filter}; }`
    );
    expect(fact.ownershipFiltered).toBe(false);
  });

  // The other direction: real identity expressions must still be recognised, or
  // the reasoner starts inventing attack paths against routes that ARE scoped —
  // which this file's header calls the worst possible error.
  it.each([
    ["a direct user id", '.eq("user_id", user.id)'],
    ["an optional-chained user id", '.eq("user_id", user?.id)'],
    ["a Supabase auth.uid() call", '.eq("id", auth.uid())'],
    ["a JWT claim", '.eq("tenant_id", claims.sub)'],
    ["a camelCase identifier", '.eq("owner", userId)'],
    ["a nested request user", '.eq("uid", req.user.id)'],
  ])("still recognises %s as an ownership filter", (_label, filter) => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() { return supabase.from("t").select("*")${filter}; }`
    );
    expect(fact.ownershipFiltered).toBe(true);
  });

  it("recognises ownership via a session object", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() { return supabase.from("t").select().eq("owner_id", session.user.id); }`
    );
    expect(fact.ownershipFiltered).toBe(true);
  });

  // A bare header read is not a session. The same code shape reads a shared
  // secret (corpus-a's SCIM endpoint hands the bearer to @boxyhq/saml-jackson), so
  // the honest fact is "there is a credential check here we could not read".
  it("treats a bare bearer-header read as unreadable, never as a user session", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function POST(req) { const t = req.headers.get("authorization"); }`
    );
    expect(fact.authenticated).toBe(false);
    expect(fact.machineGated).toBe(false);
    expect(fact.identityReadable).toBe(false);
    expect(fact.identityGap).toMatch(/Authorization header/);
  });

  // Commented-out code is not behaviour.
  it("ignores a table reference that only appears in a comment", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() {
         // return supabase.from("secrets").select("*")
         return new Response("ok");
       }`
    );
    expect(fact.tables).toEqual([]);
  });

  it("ignores an auth call that is commented out", () => {
    const fact = analyzeRouteFile(
      "app/api/x/route.ts",
      `export async function GET() {
         /* await supabase.auth.getUser(); */
         return supabase.from("t").select();
       }`
    );
    expect(fact.authenticated).toBe(false);
  });
});

describe("collectRoutes", () => {
  // Step 7I: two apps in one monorepo serving the same path (corpus-e has
  // /api/trpc/lambda/[trpc] in three apps). A path is what hypotheses,
  // findings and notes key on, so colliding paths are qualified by app.
  it("qualifies a path only when two apps serve it", () => {
    const routes = collectRoutes([
      file("apps/web/src/app/api/trpc/[trpc]/route.ts", `export async function POST(){ return supabase.from("a").select() }`),
      file("apps/dashboard/src/app/api/trpc/[trpc]/route.ts", `export async function POST(){ return supabase.from("b").select() }`),
      file("apps/web/src/app/api/health/route.ts", `export async function GET(){ return new Response("ok") }`),
    ]);
    expect(routes.map((r) => [r.path, r.tables])).toEqual([
      ["/api/health", []],
      ["apps/dashboard:/api/trpc/[trpc]", ["b"]],
      ["apps/web:/api/trpc/[trpc]", ["a"]],
    ]);
  });

  it("collects only route files, sorted by path", () => {
    const routes = collectRoutes([
      file("app/api/zeta/route.ts", `export async function GET(){ return supabase.from("z").select() }`),
      file("app/api/alpha/route.ts", `export async function GET(){ return supabase.from("a").select() }`),
      file("components/Form.tsx", `"use client"; export const F = () => null;`),
      file("lib/util.ts", `export const x = 1;`),
    ]);
    expect(routes.map((r) => r.path)).toEqual(["/api/alpha", "/api/zeta"]);
  });

  // "This endpoint exists and touches no data" is a fact the graph wants.
  it("keeps routes that touch no tables", () => {
    const routes = collectRoutes([
      file("app/api/health/route.ts", `export async function GET(){ return new Response("ok") }`),
    ]);
    expect(routes).toHaveLength(1);
    expect(routes[0].tables).toEqual([]);
  });

  it("handles an empty file list", () => {
    expect(collectRoutes([])).toEqual([]);
  });
});

describe("tablesToRoutes", () => {
  it("inverts the mapping so the graph can ask who exposes a table", () => {
    const routes = collectRoutes([
      file("app/api/a/route.ts", `export async function GET(){ return supabase.from("invoices").select() }`),
      file("app/api/b/route.ts", `export async function POST(){ return supabase.from("invoices").insert({}) }`),
      file("app/api/c/route.ts", `export async function GET(){ return supabase.from("orders").select() }`),
    ]);
    const map = tablesToRoutes(routes);
    expect(map.get("invoices")?.map((r) => r.path)).toEqual(["/api/a", "/api/b"]);
    expect(map.get("orders")?.map((r) => r.path)).toEqual(["/api/c"]);
    expect(map.has("nothing")).toBe(false);
  });

  it("returns an empty map for no routes", () => {
    expect(tablesToRoutes([]).size).toBe(0);
  });
});

// This model came directly out of dogfooding. Reading the route file alone made
// 20 of ShipLock's own 34 routes look unauthenticated; naive import following
// then made the Stripe webhook and the public ingest endpoint look
// user-authenticated. Both errors are dangerous in opposite directions.
describe("gate classification — user session vs machine secret vs open", () => {
  const files = (...entries: [string, string][]) => entries.map(([path, content]) => ({ path, content }));

  it("finds auth delegated to an imported helper", () => {
    const routes = collectRoutes(
      files(
        ["app/api/x/route.ts", `import { requireProUser } from "@/lib/gate";\nexport async function POST(){ const u = await requireProUser(); return supabase.from("t").select() }`],
        ["lib/gate.ts", `export async function requireProUser(){ const { data } = await supabase.auth.getUser(); return data.user }`]
      )
    );
    expect(routes[0].authenticated).toBe(true);
    expect(routes[0].via).toContain("lib/gate.ts");
  });

  // Step 7H: a NextAuth v5 config module (corpus-e) writes users and viewers
  // from its sign-in callbacks. Once Drizzle writes were read, every page that
  // calls auth() was credited with those tables.
  it("does not credit a NextAuth v5 config module's own writes to routes that call auth()", () => {
    const routes = collectRoutes(
      files(
        ["app/api/feed/route.ts", `import { auth } from "@/lib/auth";\nexport async function GET(){ const session = await auth(); return db.select().from(page) }`],
        ["lib/auth.ts", `import NextAuth from "next-auth";\nexport const { handlers, auth } = NextAuth({ callbacks: { async signIn({ user }) { await db.update(viewer).set({ seen: 1 }); return true; } } });`]
      )
    );
    expect(routes[0].tables).toEqual(["page"]);
    expect(routes[0].authenticated).toBe(true);
  });

  it("finds tables reached through an imported helper", () => {
    const routes = collectRoutes(
      files(
        ["app/api/x/route.ts", `import { load } from "@/lib/load";\nexport async function GET(){ return load() }`],
        ["lib/load.ts", `export const load = () => admin.from("deep_findings").select("*")`]
      )
    );
    expect(routes[0].tables).toEqual(["deep_findings"]);
  });

  // Setting an outbound Authorization header is not a gate. This mistake made
  // every module that calls an external API look like it authenticated callers.
  it("does NOT count an outbound Authorization header as authentication", () => {
    const routes = collectRoutes(
      files(
        ["app/api/ingest/route.ts", `import { push } from "@/lib/push";\nexport async function POST(){ return push() }`],
        ["lib/push.ts", `export const push = () => fetch(url, { headers: { Authorization: \`Bearer \${token}\` } })`]
      )
    );
    expect(routes[0].authenticated).toBe(false);
    expect(routes[0].machineGated).toBe(false);
  });

  it("reads an inbound Authorization header as a gate we could not classify, not as a session", () => {
    const routes = collectRoutes(
      files(["app/api/x/route.ts", `export async function GET(req){ const t = req.headers.get("authorization"); return supabase.from("t").select() }`])
    );
    expect(routes[0].authenticated).toBe(false);
    expect(routes[0].identityReadable).toBe(false);
  });

  it("classifies a Stripe-signature webhook as machine-gated, not user-authenticated", () => {
    const routes = collectRoutes(
      files(["app/api/webhook/route.ts", `export async function POST(req){ const e = stripe.webhooks.constructEvent(body, sig, secret); return admin.from("user_profiles").update({}) }`])
    );
    expect(routes[0].machineGated).toBe(true);
    expect(routes[0].authenticated).toBe(false);
  });

  // A cron endpoint comparing Bearer <CRON_SECRET> reads an inbound header, but
  // there is no user. Claiming one would fire "authenticated route reads
  // user_profiles unfiltered" on every cron route.
  it("treats a header read next to a shared secret as a machine gate, not a session", () => {
    const routes = collectRoutes(
      files(["app/api/cron/route.ts", `export async function GET(req){ if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response("no"); return admin.from("user_profiles").select() }`])
    );
    expect(routes[0].machineGated).toBe(true);
    expect(routes[0].authenticated).toBe(false);
  });

  // A real user session alongside a secret is still a user session.
  it("keeps user auth when a STRONG identity signal is present too", () => {
    const routes = collectRoutes(
      files(["app/api/x/route.ts", `export async function GET(req){ const { data } = await supabase.auth.getUser(); const h = createHmac("sha256", k); return supabase.from("t").select() }`])
    );
    expect(routes[0].authenticated).toBe(true);
    expect(routes[0].machineGated).toBe(true);
  });

  it("recognises a path/body secret token compared against the database", () => {
    const routes = collectRoutes(
      files(["app/api/monitor/[token]/route.ts", `export async function POST(){ return admin.from("user_profiles").select().eq("monitor_webhook_token", token) }`])
    );
    expect(routes[0].machineGated).toBe(true);
  });

  it("leaves a genuinely public endpoint as neither", () => {
    const routes = collectRoutes(
      files(["app/auth/callback/route.ts", `export async function GET(req){ const code = new URL(req.url).searchParams.get("code"); return NextResponse.redirect("/") }`])
    );
    expect(routes[0].authenticated).toBe(false);
    expect(routes[0].machineGated).toBe(false);
  });

  it("does not credit a helper's machine-gate mention to the route that imports it", () => {
    const routes = collectRoutes(
      files(
        ["app/api/x/route.ts", `import { h } from "@/lib/h";\nexport async function GET(){ return h() }`],
        ["lib/h.ts", `export const h = () => process.env.CRON_SECRET`]
      )
    );
    expect(routes[0].machineGated).toBe(false);
  });

  it("terminates on a circular import", () => {
    const routes = collectRoutes(
      files(
        ["app/api/x/route.ts", `import { a } from "@/lib/a";\nexport async function GET(){ return a() }`],
        ["lib/a.ts", `import { b } from "@/lib/b";\nexport const a = () => b()`],
        ["lib/b.ts", `import { a } from "@/lib/a";\nexport const b = () => a()`]
      )
    );
    expect(routes).toHaveLength(1);
  });
});

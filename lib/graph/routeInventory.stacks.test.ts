import { describe, expect, it } from "vitest";
import { collectRoutes, withoutIdentityResolution } from "./routeInventory";

/**
 * The inventory was written against Supabase and quietly misread every other
 * stack in the ICP. Found by running the pipeline on a Clerk + Drizzle route
 * carrying a real tenant-isolation bug, which came back as authenticated:
 * false, tables: [] and ownershipFiltered: TRUE -- three wrong answers, the
 * last of which is a fail-open on the check class this product exists for.
 *
 * Both directions are asserted for each stack. A detector that finds the bug by
 * calling everything unscoped is not a detector.
 */

const route = (content: string) => collectRoutes([{ path: "app/api/x/route.ts", content }])[0];

describe("Clerk", () => {
  it("counts await auth() as resolving a user", () => {
    const r = route(`
      import { auth } from "@clerk/nextjs/server";
      export async function GET() { const { userId } = await auth(); return db.query.notes.findMany(); }
    `);
    expect(r.authenticated).toBe(true);
  });

  it("does not treat obtaining an id as filtering by it", () => {
    // const { userId } = await auth() contains "userId", which the ownership
    // pattern matches. Counting that as a filter reported an unscoped route as
    // scoped and the finding never appeared.
    const r = route(`
      import { auth } from "@clerk/nextjs/server";
      export async function GET(req, { params }) {
        const { userId } = await auth();
        if (!userId) return new Response("Unauthorized", { status: 401 });
        return db.query.invoices.findFirst({ where: eq(invoices.id, params.id) });
      }
    `);
    expect(r.ownershipFiltered).toBe(false);
    expect(r.tables).toEqual(["invoices"]);
  });

  it("still sees a genuine ownership filter on the next line", () => {
    const r = route(`
      import { auth } from "@clerk/nextjs/server";
      export async function GET(req, { params }) {
        const { userId } = await auth();
        if (!userId) return new Response("Unauthorized", { status: 401 });
        return db.query.workspaces.findFirst({
          where: and(eq(workspaces.id, params.id), eq(workspaces.ownerId, userId)),
        });
      }
    `);
    expect(r.ownershipFiltered).toBe(true);
  });
});

describe("table access that does not name the table in a string", () => {
  it("reads Drizzle query access", () => {
    expect(route("export async function GET(){ return db.query.invoices.findFirst() }").tables).toEqual(["invoices"]);
  });

  it("reads Drizzle select-from with an identifier", () => {
    expect(route("export async function GET(){ return db.select().from(invoices) }").tables).toEqual(["invoices"]);
  });

  it("reads Prisma model access", () => {
    expect(route("export async function GET(){ return prisma.invoice.findMany() }").tables).toEqual(["invoice"]);
  });

  it("does not mistake query-builder plumbing for a table", () => {
    // An entry that reaches no table cannot produce an attack path, so a fake
    // table is not harmless noise -- it invents reachability.
    expect(route("export async function GET(){ return db.select().from(sql) }").tables).toEqual([]);
  });

  it("still reads Supabase string access", () => {
    expect(route('export async function GET(){ return supabase.from("orders").select() }').tables).toEqual(["orders"]);
  });
});

describe("withoutIdentityResolution", () => {
  it("removes the destructure and the null guard, and nothing else", () => {
    const stripped = withoutIdentityResolution(`
      const { userId } = await auth();
      if (!userId) return new Response("Unauthorized", { status: 401 });
      const rows = await db.select().from(notes).where(eq(notes.ownerId, userId));
    `);
    expect(stripped).not.toMatch(/await auth\(\)/);
    expect(stripped).toContain("notes.ownerId");
  });

  it("keeps a guard that does something other than refuse", () => {
    const stripped = withoutIdentityResolution(
      "if (!userId) { scope = publicScope; audit(userId); }",
    );
    expect(stripped).toContain("audit(userId)");
  });
});

describe("built-in .from() is not a table read", () => {
  it("does not credit a route with a table named after a Buffer argument", () => {
    // Reading ShipLock's own repository, `Buffer.from(contentUtf8, "utf8")`
    // was collected as a table called contentUtf8. A route credited with a
    // table it never touches is a route the graph believes reaches data —
    // a false attack path waiting to happen.
    const fact = collectRoutes([{ path: "app/api/upload/route.ts", content: `export async function POST(req) {
         const body = await req.text();
         const encoded = Buffer.from(body, "utf8").toString("base64");
         const rows = Array.from(new Set([encoded]));
         return Response.json(rows);
       }` }])[0];
    expect(fact.tables).toEqual([]);
  });

  it("still reads a real Drizzle from(table)", () => {
    const fact = collectRoutes([{ path: "app/api/invoices/route.ts", content: `import { db } from "@/db";
       export async function GET() {
         return Response.json(await db.select().from(invoices));
       }` }])[0];
    expect(fact.tables).toContain("invoices");
  });
});

describe("monorepo layouts, because startup codebases are monorepos", () => {
  // Auditing corpus-g (2,359 files, 112 tables) returned ZERO routes: every
  // endpoint sits under apps/web/src/app/ and the matcher required the path to
  // start with app/. The agent then skipped the run with "no route reaches a
  // table", so the largest codebases were the ones we said nothing about.
  it("finds routes in a workspace, and reports the real URL", () => {
    const facts = collectRoutes([
      {
        path: "apps/web/src/app/api/invoices/[id]/route.ts",
        content: `export async function GET() { return Response.json(await db.select().from(invoices)); }`,
      },
      {
        path: "apps/admin/app/api/users/route.ts",
        content: `export async function GET() { return Response.json(1); }`,
      },
      {
        path: "packages/api/src/pages/api/legacy.ts",
        content: `export default function handler(req, res) { res.json({}); }`,
      },
    ]);
    const paths = facts.map((f) => f.path).sort();
    expect(paths).toEqual(["/api/invoices/[id]", "/api/legacy", "/api/users"]);
  });

  it("still refuses a route.ts that is not under an app directory", () => {
    const facts = collectRoutes([
      { path: "lib/trpc/route.ts", content: "export async function GET() {}" },
      { path: "docs/examples/route.ts", content: "export async function GET() {}" },
    ]);
    expect(facts).toHaveLength(0);
  });

  it("keeps the plain single-app layout working", () => {
    const facts = collectRoutes([
      { path: "app/api/scan/route.ts", content: "export async function POST() {}" },
      { path: "src/app/api/other/route.ts", content: "export async function GET() {}" },
    ]);
    expect(facts.map((f) => f.path).sort()).toEqual(["/api/other", "/api/scan"]);
  });
});

describe("an identity the caller supplied is not an identity", () => {
  // Found on a real repository: a route destructured userId from the request
  // body and updated that row. OWNERSHIP_RE saw the NAME and marked it
  // owner-filtered, and once the prompt began telling the model to trust that
  // label, the genuine vulnerability vanished from the report. A fail-open on
  // the one check class this product exists for.
  const route = (content: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content }])[0];

  it("does not count a body-supplied user id as an ownership filter", () => {
    const fact = route(`export async function POST(request) {
      const { userId, avatarUrl } = await request.json();
      await supabase.from('users').update({ avatar_url: avatarUrl }).eq('id', userId);
      return Response.json({});
    }`);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("does not count a query-parameter user id either", () => {
    const fact = route(`export async function GET(request) {
      const userId = request.nextUrl.searchParams.get('userId');
      await supabase.from('orders').select('*').eq('user_id', userId);
      return Response.json({});
    }`);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("sees through a rename in the destructure", () => {
    const fact = route(`export async function POST(request) {
      const { userId: ownerId } = await request.json();
      await supabase.from('users').update({ x: 1 }).eq('id', ownerId);
      return Response.json({});
    }`);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("sees through a TypeScript annotation on the destructure", () => {
    // The repository that exposed this fail-open writes it exactly this way,
    // and the pattern expected `}` followed directly by `=`.
    const fact = route(`export async function POST(request: Request) {
      const { userId, avatarUrl }: { userId: string; avatarUrl: string } = await request.json();
      await supabase.from('users').update({ avatar_url: avatarUrl }).eq('id', userId);
      return Response.json({});
    }`);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("still counts a session identity, however it is obtained", () => {
    // The other direction matters just as much. Inventing an attack path for a
    // correctly scoped route is what this file's header calls the worst outcome.
    expect(
      route(`export async function GET() {
        const { userId } = await auth();
        await supabase.from('users').select('*').eq('id', userId);
        return Response.json({});
      }`).ownershipFiltered,
    ).toBe(true);

    expect(
      route(`export async function GET() {
        const user = await requireProUser();
        await admin.from('audit_runs').select('*').eq('user_id', user.userId);
        return Response.json({});
      }`).ownershipFiltered,
    ).toBe(true);
  });
});

describe("an auth helper does not scope the route that imports it", () => {
  // requireProUser does `.eq("id", user.id)` to fetch the profile of whoever is
  // signed in. That is identity construction, not row scoping, and counting it
  // made EVERY route importing it read as owner-filtered whether it filtered or
  // not. Found when the merge check passed a route reading a table by an id
  // taken straight from the URL.
  const authHelper = {
    path: "lib/deep/proGate.ts",
    content: `import { getSupabaseServer } from "@/lib/supabaseServer";
      export async function requireProUser() {
        const supabase = await getSupabaseServer();
        const { data: { user } } = await supabase.auth.getUser();
        if (!user) return null;
        const { data } = await admin.from("user_profiles").select("is_paid").eq("id", user.id).single();
        return { userId: user.id, email: user.email };
      }`,
  };

  const collect = (route: { path: string; content: string }) =>
    collectRoutes([authHelper, route]).find((r) => r.file === route.path)!;

  it("reads an unscoped route as unscoped even when it authenticates", () => {
    const fact = collect({
      path: "app/api/scan-history/[id]/route.ts",
      content: `import { requireProUser } from "@/lib/deep/proGate";
        export async function GET(_req, context) {
          const user = await requireProUser();
          if (!user) return Response.json({ error: "no" }, { status: 401 });
          const { id } = await context.params;
          const { data } = await admin.from("scan_history").select("*").eq("id", id).single();
          return Response.json(data);
        }`,
    });
    expect(fact.authenticated).toBe(true);
    expect(fact.ownershipFiltered).toBe(false);
  });

  it("still reads a genuinely scoped route as scoped", () => {
    // The other direction is the one that matters more: inventing a path for a
    // correctly scoped route is the worst outcome this file has.
    const fact = collect({
      path: "app/api/tokens/route.ts",
      content: `import { requireProUser } from "@/lib/deep/proGate";
        export async function GET() {
          const ctx = await requireProUser();
          const { data } = await admin.from("api_tokens").select("*").eq("user_id", ctx.userId);
          return Response.json(data);
        }`,
    });
    expect(fact.authenticated).toBe(true);
    expect(fact.ownershipFiltered).toBe(true);
  });

  it("still credits a DATA helper that scopes on the route's behalf", () => {
    // A helper that does not resolve identity is doing the route's filtering,
    // so its ownership evidence still counts.
    const dataHelper = {
      path: "lib/scanHistory.ts",
      content: `export async function historyFor(userId) {
        return admin.from("scan_history").select("*").eq("user_id", userId);
      }`,
    };
    const fact = collectRoutes([
      authHelper,
      dataHelper,
      {
        path: "app/api/history/route.ts",
        content: `import { requireProUser } from "@/lib/deep/proGate";
          import { historyFor } from "@/lib/scanHistory";
          export async function GET() {
            const ctx = await requireProUser();
            return Response.json(await historyFor(ctx.userId));
          }`,
      },
    ]).find((r) => r.file === "app/api/history/route.ts")!;
    expect(fact.ownershipFiltered).toBe(true);
  });
});

describe("an auth helper's own query is not the route's data access", () => {
  // requireProUser selects from user_profiles to check the gate. Crediting that
  // to the importer made /api/deep/github/connect, whose entire body is a
  // redirect and which queries nothing, report CRITICAL for reading
  // user_profiles without narrowing it to the caller.
  const authHelper = {
    path: "lib/deep/proGate.ts",
    content: `export async function requireProUser() {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return null;
      const { data } = await admin.from("user_profiles").select("is_paid").eq("id", user.id).single();
      return data?.is_paid ? { userId: user.id } : null;
    }`,
  };

  it("credits no table to a route that only redirects", () => {
    const fact = collectRoutes([
      authHelper,
      {
        path: "app/api/deep/github/connect/route.ts",
        content: `import { requireProUser } from "@/lib/deep/proGate";
          export async function GET() {
            const pro = await requireProUser();
            if (!pro) return Response.redirect("/dashboard?github=forbidden", 303);
            return Response.redirect("https://github.com/apps/x/installations/new", 303);
          }`,
      },
    ]).find((r) => r.path === "/api/deep/github/connect")!;

    expect(fact.authenticated).toBe(true);
    expect(fact.tables).toEqual([]);
  });

  it("still credits the tables the route queries itself", () => {
    const fact = collectRoutes([
      authHelper,
      {
        path: "app/api/tokens/route.ts",
        content: `import { requireProUser } from "@/lib/deep/proGate";
          export async function GET() {
            const ctx = await requireProUser();
            const { data } = await admin.from("api_tokens").select("*").eq("user_id", ctx.userId);
            return Response.json(data);
          }`,
      },
    ]).find((r) => r.path === "/api/tokens")!;

    expect(fact.tables).toContain("api_tokens");
    expect(fact.ownershipFiltered).toBe(true);
  });
});

// Auth mechanisms found by auditing five real startup codebases (corpus-a,
// corpus-c, corpus-e, corpus-b, corpus-d). Each one read as ANONYMOUS, and
// each produced a CRITICAL "anyone on the internet can call this endpoint".
describe("auth this inventory did not recognise", () => {
  const route = (src: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }] as never)[0];

  it("sees an Upstash QStash receiver as a machine gate", () => {
    const r = route(`
      import { receiver } from "@/lib/cron";
      export async function POST(req: Request) {
        const isValid = await receiver.verify({ signature: req.headers.get("Upstash-Signature") || "", body: "" });
        if (!isValid) return new Response("Unauthorized", { status: 401 });
        return Response.json(await prisma.dataroom.findMany());
      }`);
    expect(r.machineGated).toBe(true);
  });

  it("sees a signature verifier behind a project-specific name", () => {
    // `verifySignature` did not match `verifyQstashSignature`.
    const r = route(`
      import { verifyQstashSignature } from "@/lib/cron/verify-qstash";
      export const POST = async (req: Request) => {
        await verifyQstashSignature({ req, rawBody: await req.text() });
        return Response.json(await prisma.webhook.findUnique({ where: { pId: "x" } }));
      };`);
    expect(r.machineGated).toBe(true);
  });

  it("sees a header compared against an environment secret", () => {
    const r = route(`
      export async function POST(req) {
        const token = req.headers.authorization?.split(" ")[1];
        if (token !== process.env.INTERNAL_API_KEY) return res.status(401).json({ message: "Unauthorized" });
        return Response.json(await prisma.dataroomDocument.findMany());
      }`);
    expect(r.machineGated).toBe(true);
  });

  it("does NOT treat reading a provider secret as a gate", () => {
    // Using STRIPE_SECRET_KEY to call Stripe is not authentication. Treating it
    // as one would silence the real finding on this exact route.
    const r = route(`
      export async function POST(req) {
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
        const { id } = await req.json();
        return Response.json(await prisma.subscription.delete({ where: { id } }));
      }`);
    expect(r.machineGated).toBe(false);
    expect(r.authenticated).toBe(false);
  });

  it("sees a project-specific session verifier as user authentication", () => {
    const r = route(`
      import { verifyDataroomSession } from "@/lib/auth/dataroom-auth";
      export async function GET(req) {
        const session = await verifyDataroomSession(req, linkId, dataroomId);
        if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        return NextResponse.json(await prisma.dataroomFaqItem.findMany());
      }`);
    expect(r.authenticated).toBe(true);
  });
});

// Every route below is real, taken from the five startup codebases audited on
// 2026-09-01, and every one was reported as a CRITICAL "anyone on the internet
// can call this endpoint". Thirteen of fourteen false criticals were this.
describe("a route we cannot read is not a route with no gate", () => {
  const route = (src: string, extra: { path: string; content: string }[] = []) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }, ...extra] as never)[0];

  it("does not call a wrapped handler anonymous (corpus-a: 435 of 511 routes)", () => {
    const r = route(`
      import { withWorkspace } from "@/lib/auth";
      export const GET = withWorkspace(async ({ workspace }) => {
        return NextResponse.json(await prisma.link.findMany());
      });`);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/withWorkspace/);
  });

  it("does not call a cookie-session route anonymous (corpus-b)", () => {
    const r = route(`
      import { parse as parseCookieHeader } from "cookie";
      export default async function handler(req, res) {
        const cookies = parseCookieHeader(req.headers.cookie || "");
        const accessCookie = cookies[getSignedAgreementAccessCookieName(linkId)];
        return res.json(await prisma.agreementResponse.findMany());
      }`);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/cookie/i);
  });

  it("does not call a route that answers 401 anonymous (corpus-c)", () => {
    const r = route(`
      export async function GET(req) {
        if (!authentication || !("apiKeyId" in authentication)) {
          return responses.unauthorizedResponse();
        }
        return Response.json(await prisma.survey.findMany());
      }`);
    expect(r.identityReadable).toBe(false);
  });

  it("does not call a route anonymous when its auth import was never read", () => {
    const r = route(`
      import { verifyDataroomSession } from "@/lib/auth/dataroom-auth";
      export async function GET(req) {
        return Response.json(await prisma.faq.findMany());
      }`);
    // The helper file is outside this file set, so we never saw what it does.
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/dataroom-auth/);
  });

  // THE OTHER DIRECTION, and the one that matters more: the cure must not be
  // silence. A route with genuinely nothing guarding it still reports.
  it("STILL calls a genuinely open route anonymous", () => {
    const r = route(`
      import prisma from "@/lib/prisma";
      export default async function handler(req, res) {
        const { documentVersionId } = req.query;
        const v = await prisma.documentVersion.findUnique({ where: { id: documentVersionId } });
        res.status(200).json(v);
      }`);
    expect(r.identityReadable).toBe(true);
    expect(r.authenticated).toBe(false);
    expect(r.machineGated).toBe(false);
  });

  it("does not treat a plain database import as a possible gate", () => {
    // The first version of this fired on @/lib/supabase and silenced a real
    // finding. Only a module that could plausibly BE the gate counts.
    const r = route(`
      import { getSupabaseAdmin } from "@/lib/supabase";
      export async function GET() {
        return Response.json(await getSupabaseAdmin().from("orders").select("*"));
      }`);
    expect(r.identityReadable).toBe(true);
  });

  it("does not mark a route we DID read as unreadable", () => {
    const r = route(
      `import { requireUser } from "@/lib/guard";
       export async function GET(req) {
         const user = await requireUser(req);
         return Response.json(await supabase.from("orders").select("*").eq("user_id", user.id));
       }`,
      [{ path: "lib/guard.ts", content: `export async function requireUser(req) { return getSession(req); }` }],
    );
    expect(r.identityReadable).toBe(true);
    expect(r.authenticated).toBe(true);
  });

  it("a neutral wrapper is not treated as a gate", () => {
    const r = route(`
      export const GET = handler(async (req) => {
        return Response.json(await prisma.post.findMany());
      });`);
    expect(r.identityReadable).toBe(true);
  });
});

// The wrapper-parse bug. `async` is a keyword, not a wrapper name, and treating
// it as one suppressed corpus-a's /api/links/exists — a genuinely unauthenticated
// endpoint taking workspaceId from the query string. 45 routes across five real
// codebases were mis-captured this way.
describe("a keyword is not a wrapper", () => {
  const route = (src: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }] as never)[0];

  const OPEN_BODY = `
        const { workspaceId } = getSearchParams(req.url);
        const ws = await getWorkspaceViaEdge({ workspaceId });
        return NextResponse.json(await prisma.link.findMany({ where: { workspaceId } }));`;

  it("reads an async arrow handler as READABLE, not wrapped", () => {
    const r = route(`export const GET = async (req: NextRequest) => {${OPEN_BODY}\n};`);
    expect(r.identityReadable).toBe(true);
    expect(r.authenticated).toBe(false);
    expect(r.machineGated).toBe(false);
  });

  it("reads a plain arrow handler as readable", () => {
    const r = route(`export const GET = (req) => {${OPEN_BODY}\n};`);
    expect(r.identityReadable).toBe(true);
  });

  it("does not treat `new` as a wrapper", () => {
    const r = route(`export const POST = new Handler({ run: async (req) => {${OPEN_BODY}\n} });`);
    expect(r.identityReadable).toBe(true);
  });

  it("STILL suppresses a genuine wrapper", () => {
    const r = route(`export const GET = withWorkspace(async ({ workspace }) => {${OPEN_BODY}\n});`);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/withWorkspace/);
  });

  it("does not suppress on a logging decorator", () => {
    const r = route(`export const GET = withAxiom(async (req) => {${OPEN_BODY}\n});`);
    expect(r.identityReadable).toBe(true);
  });

  it("a typed async arrow is still readable", () => {
    const r = route(`export const GET: RouteHandler = async (req) => {${OPEN_BODY}\n};`);
    expect(r.identityReadable).toBe(true);
  });
});

// The injected-context signal, narrowed. It fired on twelve routes across the
// five audited repositories and was wrong on all twelve.
describe("injected tenant context is a function parameter, not any object", () => {
  const route = (body: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: body }] as never)[0];

  const READ = `const { id } = req.query;\n  const rows = await prisma.doc.findMany();`;

  it("does not fire on an error message mentioning a workspace", () => {
    const r = route(`export async function GET(req) {\n  ${READ}\n  return NextResponse.json({ error: "No workspace slug provided." }, { status: 400 });\n}`);
    expect(r.ownershipReadable).toBe(true);
  });

  it("does not fire on a prisma where clause — that IS the filter", () => {
    const r = route(`export async function GET(req) {\n  const v = await prisma.view.findUnique({ where: { id: viewerId, teamId } });\n  return Response.json(v);\n}`);
    expect(r.ownershipReadable).toBe(true);
  });

  it("does not fire on an outbound call carrying a tenant value", () => {
    const r = route(`export async function GET(req) {\n  ${READ}\n  await sendEmail({ stripeId: workspace.stripeId, amount: 1 });\n  return Response.json(rows);\n}`);
    expect(r.ownershipReadable).toBe(true);
  });

  it("does not fire on a feature-flag lookup — the corpus-b case exactly", () => {
    const r = route(`export default async function handle(req, res) {\n  const { id: linkId, viewId } = req.query;\n  const view = await prisma.view.findUnique({ where: { id: viewId } });\n  const flags = await getFeatureFlags({ teamId: view.teamId || undefined });\n  res.json(view);\n}`);
    expect(r.ownershipReadable).toBe(true);
  });

  it("STILL fires on a tenant destructured as a handler parameter", () => {
    const r = route(`export const GET = someWrapper(async ({ workspace }) => {\n  return Response.json(await prisma.link.findMany());\n});`);
    expect(r.ownershipReadable).toBe(false);
  });
});

// The three collector gaps from stage 5d, fixed as a class. Every case is a
// real route from the five audited repositories.
describe("gaps found by adjudicating stable false positives", () => {
  const route = (src: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }] as never)[0];

  // 2.1 — a header bag assigned to a local before it is read (corpus-b SCIM).
  it("sees an Authorization header read through a local bag", () => {
    const r = route(`
      import { headers } from "next/headers";
      export async function POST(req) {
        const headersList = await headers();
        const apiSecret = headersList.get("Authorization")?.split(" ")[1];
        return Response.json(await prisma.team.findMany({ apiSecret }));
      }`);
    expect(r.authenticated || !r.identityReadable).toBe(true);
  });

  // 2.2 — a credential check we cannot classify is UNREADABLE, never "authenticated".
  it("treats an unclassifiable token verifier as unreadable, not as a gate", () => {
    const r = route(`
      import { verifyUnsubscribeToken } from "@/lib/utils/unsubscribe";
      export default async function handle(req, res) {
        const { token } = req.query;
        const ok = verifyUnsubscribeToken(token);
        return res.json(await prisma.userTeam.findMany());
      }`);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/could not classify/);
    // The trade: we do NOT claim it authenticates.
    expect(r.authenticated).toBe(false);
  });

  // 2.3 — provenance, not vocabulary (corpus-b conversations).
  it("does not count a caller-supplied viewerId as an ownership filter", () => {
    const r = route(`
      export default async function handler(req, res) {
        const { dataroomId, viewerId } = req.query;
        const rows = await prisma.conversation.findMany({ where: { viewerId, dataroomId } });
        return res.json(rows);
      }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("covers identity names no wordlist would have listed", () => {
    for (const name of ["partnerId", "contactId", "memberId", "subscriberId", "patientId"]) {
      const r = route(`
        export default async function handler(req, res) {
          const { ${name} } = req.query;
          return res.json(await prisma.thing.findMany({ where: { ${name} } }));
        }`);
      expect(r.ownershipFiltered, `${name} must not read as ownership`).toBe(false);
    }
  });

  // The other direction: a session-derived id still counts.
  it("STILL counts a session-derived id as an ownership filter", () => {
    const r = route(`
      import { getServerSession } from "next-auth";
      export default async function handler(req, res) {
        const session = await getServerSession();
        const rows = await prisma.doc.findMany({ where: { ownerId: session.user.id } });
        return res.json(rows);
      }`);
    expect(r.authenticated).toBe(true);
    expect(r.ownershipFiltered).toBe(true);
  });
});

// The SCIM blocker. corpus-a's app/(ee)/api/scim/v2.0/[...directory]/route.ts reads
// `headersList.get("Authorization")` and hands the bearer secret to
// @boxyhq/saml-jackson. HEADER_READ_RE fed that into `authenticated: true`, so
// a machine-to-machine endpoint with no caller-user was judged as a user route
// that "does not narrow to the caller", and the merge check BLOCKED on it.
//
// The rule, stated once: a bare Authorization header read, with no recognised
// machine gate and no session call, is not user authentication. It is a
// credential check we could not classify, and it lands where those already
// land -- identityReadable: false -- disclosed as unassessed, never asserted.
describe("a bare Authorization header read is not a user session", () => {
  const route = (src: string, extra: { path: string; content: string }[] = []) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }, ...extra] as never)[0];

  it("SCIM: a bearer handed to a library is unreadable, not authenticated", () => {
    const r = route(`
      import { jackson } from "@/lib/jackson";
      import { headers } from "next/headers";
      const handler = async (req: Request) => {
        const headersList = await headers();
        const authHeader = headersList.get("Authorization");
        const apiSecret = authHeader ? authHeader.split(" ")[1] : null;
        const { directorySyncController } = await jackson();
        const { status, data } = await directorySyncController.requests.handle({ apiSecret }, handleEvents);
        await prisma.projectUsers.findMany();
        return NextResponse.json(data, { status });
      };
      export { handler as DELETE, handler as GET, handler as POST, handler as PUT };`);
    expect(r.authenticated).toBe(false);
    expect(r.machineGated).toBe(false);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/Authorization header/);
    // Unreadable identity means the scope is unreadable too: no diffScan block.
    expect(r.ownershipReadable).toBe(false);
  });

  it("a direct req.headers.get('authorization') with nothing else is unreadable", () => {
    const r = route(`
      export async function GET(req: Request) {
        const token = req.headers.get("authorization")?.replace("Bearer ", "");
        const rows = await prisma.apiKey.findMany({ where: { hashedKey: hash(token) } });
        return Response.json(rows);
      }`);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(false);
  });

  it("a header read next to a recognised machine gate is STILL a machine gate", () => {
    const r = route(`
      import { timingSafeEqual } from "crypto";
      export async function POST(req: Request) {
        const given = req.headers.get("authorization") ?? "";
        if (!timingSafeEqual(Buffer.from(given), Buffer.from(process.env.CRON_SECRET!))) return new Response("no", { status: 401 });
        return Response.json(await prisma.job.findMany());
      }`);
    expect(r.machineGated).toBe(true);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });

  it("a header read next to a session call is STILL a user session", () => {
    const r = route(`
      import { getServerSession } from "next-auth";
      export async function GET(req: Request) {
        const bearer = req.headers.get("authorization");
        const session = await getServerSession(authOptions);
        if (!session) return new Response("no", { status: 401 });
        return Response.json(await prisma.doc.findMany({ where: { ownerId: session.user.id } }));
      }`);
    expect(r.authenticated).toBe(true);
    expect(r.identityReadable).toBe(true);
  });

  it("a header read inside an imported helper makes the route unreadable, and names the helper", () => {
    const r = route(
      `import { bearerFrom } from "@/lib/bearer";
       export async function GET(req: Request) {
         const token = bearerFrom(req);
         return Response.json(await prisma.doc.findMany());
       }`,
      [{ path: "lib/bearer.ts", content: `export function bearerFrom(req: Request) { return req.headers.get("authorization")?.split(" ")[1]; }` }],
    );
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/lib\/bearer\.ts/);
  });

  // THE OTHER DIRECTION: the cure must not be silence.
  it("STILL calls a route with no header read and no gate anonymous", () => {
    const r = route(`
      export async function GET(req: Request) {
        const id = new URL(req.url).searchParams.get("id");
        return Response.json(await prisma.doc.findUnique({ where: { id } }));
      }`);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });

  it("an OUTBOUND Authorization header is neither a gate nor a gap", () => {
    const r = route(`
      export async function GET() {
        const res = await fetch("https://api.example.com", { headers: { Authorization: \`Bearer \${process.env.EXAMPLE_KEY}\` } });
        return Response.json(await prisma.doc.findMany());
      }`);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });
});

// The OWNERSHIP_RE tightening. Its third alternative used to match the bare
// token `userId` ANYWHERE in any file a route reaches, so it matched
// declarations, not uses: interface fields, type unions, Zod schemas, SELECT
// projections. On corpus-b 82% of routes were wrongly marked owner-filtered,
// which suppresses the tenant-isolation attack path -- a fail-open on the one
// check class the product exists for. The pattern now requires a
// filter-argument position.
//
// Every shape below is named for what it protects. An earlier draft of this
// tightening broke `.eq('user_id', user.userId)` -- a real server-established
// filter through a member expression -- and only the existing suite caught it.
// These tests exist so the next draft cannot.
describe("ownership evidence is a filter position, not a mention", () => {
  const route = (src: string, extra: { path: string; content: string }[] = []) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }, ...extra] as never)[0];
  const SESSION = `import { getServerSession } from "next-auth";\n`;

  // ── KEEP: real filters, each a different syntactic shape ──
  it("KEEP Supabase argument position: .eq('id', userId)", () => {
    const r = route(`${SESSION}export async function GET() {
      const session = await getServerSession();
      const userId = session.user.id;
      const { data } = await supabase.from("orders").select("*").eq("user_id", userId);
      return Response.json(data);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP member expression through a session object: .eq('user_id', user.userId)", () => {
    const r = route(`export async function GET() {
      const user = await requireProUser();
      await admin.from('audit_runs').select('*').eq('user_id', user.userId);
      return Response.json({});
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP Prisma shorthand: where: { userId }", () => {
    const r = route(`${SESSION}export async function GET() {
      const session = await getServerSession();
      const userId = session.user.id;
      return Response.json(await prisma.doc.findMany({ where: { userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP Prisma key-value: where: { ownerId: userId }", () => {
    const r = route(`${SESSION}export async function GET() {
      const session = await getServerSession();
      const userId = session.user.id;
      return Response.json(await prisma.doc.findMany({ where: { ownerId: userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP Prisma nested relation filter: users: { some: { userId } }", () => {
    const r = route(`${SESSION}export async function GET() {
      const session = await getServerSession();
      const userId = session.user.id;
      return Response.json(await prisma.team.findFirst({ where: { id: teamId, users: { some: { userId } } } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP Drizzle argument position: eq(notes.ownerId, ctx.userId)", () => {
    const r = route(`export async function GET() {
      const ctx = await requireProUser();
      return Response.json(await db.select().from(notes).where(eq(notes.ownerId, ctx.userId)));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP fetch-then-compare: if (doc.ownerId !== userId) return 403", () => {
    const r = route(`${SESSION}export async function GET(req, { params }) {
      const session = await getServerSession();
      const userId = session.user.id;
      const doc = await prisma.doc.findUnique({ where: { id: params.id } });
      if (doc.ownerId !== userId) return new Response("Forbidden", { status: 403 });
      return Response.json(doc);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP fetch-then-compare against a session member: doc.ownerId !== session.user.id", () => {
    const r = route(`${SESSION}export async function GET(req, { params }) {
      const session = await getServerSession();
      const doc = await prisma.doc.findUnique({ where: { id: params.id } });
      if (doc.ownerId !== session.user.id) return new Response("Forbidden", { status: 403 });
      return Response.json(doc);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("DROP a comparison whose other side is not identity: message.userId === null", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      const m = await prisma.message.findUnique({ where: { id } });
      const fromAdmin = m.userId === null ? "viewer" : "admin";
      return Response.json({ m, fromAdmin });
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("KEEP a scoping DATA helper reached through an import", () => {
    const r = route(
      `import { historyFor } from "@/lib/history";
       export async function GET() {
        const ctx = await requireProUser();
        return Response.json(await historyFor(ctx.userId));
      }`,
      [{ path: "lib/history.ts", content: `export async function historyFor(userId) {
        return admin.from("scan_history").select("*").eq("user_id", userId);
      }` }],
    );
    expect(r.ownershipFiltered).toBe(true);
  });

  // ── DROP: mentions that describe shape, not behaviour ──
  const UNSCOPED_READ = `export async function GET(req) {
    const { id } = await req.json();
    return Response.json(await prisma.doc.findUnique({ where: { id } }));
  }`;

  it("DROP an interface field in a reachable type module", () => {
    const r = route(`import type { Job } from "@/lib/types";\nimport { fmt } from "@/lib/types";\n${UNSCOPED_READ}`, [
      { path: "lib/types.ts", content: `export interface Job { id: string; userId: string; status: string }\nexport const fmt = (x) => x;` },
    ]);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a type alias with an optional field: type Args = { userId?: string }", () => {
    const r = route(`type Args = { userId?: string; limit?: number };\n${UNSCOPED_READ}`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a Zod schema: z.object({ userId: z.string() }) and .omit({ userId: true })", () => {
    const r = route(`const Input = z.object({ userId: z.string(), name: z.string() });\nconst Body = Input.omit({ userId: true });\n${UNSCOPED_READ}`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a SELECT projection: select: { userId: true }", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      return Response.json(await prisma.membership.findMany({ where: { teamId: id }, select: { userId: true, role: true } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a validation branch: if ((!viewerId && !userId) || (viewerId && userId)) throw", () => {
    const r = route(`export async function POST(req) {
      const { viewerId, userId, id } = await req.json();
      if ((!viewerId && !userId) || (viewerId && userId)) throw new Error("one of viewerId or userId");
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a quoted string mentioning the word", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      console.log("lookup by ownerId: userId", id);
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  // A template literal is code, not a string: raw SQL lives there.
  it("KEEP a raw-SQL template: sql`... where user_id = ${userId}`", () => {
    const r = route(`${SESSION}export async function GET() {
      const session = await getServerSession();
      const userId = session.user.id;
      const rows = await sql\`select * from orders where user_id = \${userId}\`;
      return Response.json(rows);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });
});

// THE DECLARATION RULE, at route level. lib/graph/declarations.ts blanks
// types, interfaces, imports, parameter bindings and projections before any
// pattern runs, so no collector can draw evidence from shape. These pin the
// shapes the tightened ownership pattern alone would still have matched.
describe("the declaration rule: shape is not behaviour", () => {
  const route = (src: string, extra: { path: string; content: string }[] = []) =>
    collectRoutes([{ path: "app/api/x/route.ts", content: src }, ...extra] as never)[0];

  it("DROP a parameter list: function f(teamId, userId)", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      return Response.json(await load(id));
    }
    async function load(teamId, userId) { return prisma.doc.findMany({ where: { teamId } }); }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a destructured parameter: async function f({ teamId, userId })", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      return Response.json(await load({ teamId: id }));
    }
    async function load({ teamId, userId }) { return prisma.doc.findMany({ where: { teamId } }); }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("KEEP the use of that parameter inside the body", () => {
    const r = route(`export async function GET() {
      const ctx = await requireProUser();
      return Response.json(await load({ userId: ctx.userId }));
    }
    async function load({ userId }) { return prisma.doc.findMany({ where: { ownerId: userId } }); }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP a membership check nested inside a select projection (corpus-a: domains/[domain]/transfer)", () => {
    const r = route(`import { getServerSession } from "next-auth";
    export async function POST(req) {
      const session = await getServerSession();
      const { newWorkspaceId } = await req.json();
      const ws = await prisma.project.findUnique({
        where: { id: newWorkspaceId },
        select: { plan: true, users: { where: { userId: session.user.id }, select: { role: true } } },
      });
      if (!ws || ws.users.length === 0) return new Response("not found", { status: 404 });
      return Response.json(ws);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("DROP a table named only inside a type: typeof prisma.user.findMany", () => {
    const r = route(`type Rows = Awaited<ReturnType<typeof prisma.user.findMany>>;
    export async function GET() { return Response.json([]); }`);
    expect(r.tables).toEqual([]);
  });

  it("DROP an imported-but-never-called session helper", () => {
    const r = route(`import { getServerSession } from "next-auth";
    export async function GET(req) {
      const { id } = await req.json();
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    }`);
    expect(r.authenticated).toBe(false);
  });

  it("DROP an imported-but-never-called signature verifier as a machine gate", () => {
    const r = route(`import { timingSafeEqual } from "crypto";
    export async function POST(req) {
      const { id } = await req.json();
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    }`);
    expect(r.machineGated).toBe(false);
  });

  it("STILL neutralises a request-supplied name whose destructure was blanked", () => {
    // The destructure is a declaration and is blanked; the USES it bound must
    // still be neutralised, which needs the names from the unblanked text.
    const r = route(`export async function POST(req) {
      const { userId } = await req.json();
      return Response.json(await prisma.doc.findMany({ where: { ownerId: userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });
});

// The pages-router half of "a value the caller supplied is not a value that
// identifies the caller". REQUEST_DESTRUCTURE_RE only knew `req.json()`,
// `req.body(` and `req.formData(` -- the app-router shapes. In pages/api the
// same read is `req.query` and `req.body` with no call, and corpus-b is
// pages/api throughout. Probed on 2026-09-02: `const { userId } = req.query`
// followed by `where: { userId }` read as owner-filtered. A fail-open on the
// one check class this product exists for, in the router half the test corpus
// mostly uses.
describe("a pages-router request value is caller-supplied too", () => {
  const page = (src: string) => collectRoutes([{ path: "pages/api/x.ts", content: src }] as never)[0];

  it("does not count a userId destructured from req.query", () => {
    const r = page(`export default async function handler(req, res) {
      const { userId } = req.query;
      return res.json(await prisma.doc.findMany({ where: { userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("does not count a userId destructured from req.body, with or without a cast", () => {
    for (const read of ["req.body", "req.body as { userId: string }"]) {
      const r = page(`export default async function handler(req, res) {
        const { userId } = ${read};
        return res.json(await prisma.doc.findMany({ where: { userId } }));
      }`);
      expect(r.ownershipFiltered, read).toBe(false);
    }
  });

  it("does not count a userId assigned from req.query.userId", () => {
    const r = page(`export default async function handler(req, res) {
      const userId = req.query.userId as string;
      return res.json(await prisma.doc.findMany({ where: { userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("STILL counts a session-derived userId in a pages route", () => {
    const r = page(`import { getServerSession } from "next-auth/next";
    export default async function handler(req, res) {
      const session = await getServerSession(req, res, authOptions);
      const userId = session.user.id;
      const { teamId } = req.query;
      return res.json(await prisma.userTeam.findUnique({ where: { userId_teamId: { userId, teamId } } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });
});

// Found by the call-path tracer, which removed the gap that had been hiding
// it: corpus-a's /api/resend/webhook verifies every request through Svix and read
// as anonymous, and the merge check blocked it.
describe("a signature check we cannot classify is unreadable, not anonymous", () => {
  const route = (src: string) => collectRoutes([{ path: "app/api/x/route.ts", content: src }] as never)[0];

  it("a member call named verify() on a library object", () => {
    const r = route(`import { Webhook } from "svix";
      export const POST = async (req: Request) => {
        const rawBody = await req.text();
        new Webhook(process.env.RESEND_WEBHOOK_SECRET!).verify(rawBody, { "svix-id": req.headers.get("svix-id")!, "svix-signature": req.headers.get("svix-signature")! });
        const { data } = JSON.parse(rawBody);
        await prisma.emailEvent.create({ data });
        return Response.json({ ok: true });
      };`);
    expect(r.authenticated).toBe(false);
    expect(r.machineGated).toBe(false);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/verify|signature/);
  });

  it("STILL calls a route with no verify and no signature header anonymous", () => {
    const r = route(`export const POST = async (req: Request) => {
      const { id } = await req.json();
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    };`);
    expect(r.identityReadable).toBe(true);
  });
});

// PROVENANCE, NOT VOCABULARY, in the other direction. /api/unsubscribe/yir
// filters `userId_teamId: { userId: viewerId, teamId }` where `viewerId` came
// out of jwt.verify(). That is a server-established scope, dropped by the
// tightening because the VALUE is not identity-shaped by name -- and it was
// safe only because the route happened to be identity-unreadable. A value
// bound from a signature verification or a session lookup is the caller's, no
// matter what it is called; a value bound from a decode or a parse is the
// caller's INPUT, no matter what it is called.
describe("a value from a verifier is the caller; a value from a decoder is the caller's input", () => {
  const page = (src: string) => collectRoutes([{ path: "pages/api/x.ts", content: src }] as never)[0];

  it("KEEP corpus-b yir: destructured from a verified JWT payload, two hops", () => {
    const r = page(`import { verifyUnsubscribeToken } from "@/lib/utils/unsubscribe";
    export default async function handle(req, res) {
      const { token } = req.query;
      const payload = verifyUnsubscribeToken(token);
      if (!payload) return res.status(404).json({ message: "Invalid token" });
      const { viewerId, teamId } = payload;
      const userTeam = await prisma.userTeam.findUnique({ where: { userId_teamId: { userId: viewerId, teamId } } });
      return res.json(userTeam);
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP a member of a session returned by a project verifier: session.viewerId", () => {
    const r = page(`import { verifyDataroomSession } from "@/lib/auth/dataroom-auth";
    export default async function handle(req, res) {
      const { linkId, dataroomId } = req.query;
      const session = await verifyDataroomSession(req, linkId, dataroomId);
      if (!session) return res.status(401).end();
      return res.json(await prisma.conversation.findMany({ where: { dataroomId, participants: { some: { viewerId: session.viewerId } } } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP a renamed destructure straight off jwt.verify(): const { sub: uid }", () => {
    const r = page(`import jwt from "jsonwebtoken";
    export default async function handle(req, res) {
      const { sub: uid } = jwt.verify(req.headers.authorization.split(" ")[1], process.env.JWT_SECRET);
      return res.json(await prisma.doc.findMany({ where: { ownerId: uid } }));
    }`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("DROP a userId read from an UNVERIFIED decode: jwt.decode(token).userId", () => {
    const r = page(`import jwt from "jsonwebtoken";
    export default async function handle(req, res) {
      const { token } = req.query;
      const payload = jwt.decode(token);
      return res.json(await prisma.doc.findMany({ where: { userId: payload.userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a userId parsed out of the body: JSON.parse(rawBody).userId", () => {
    const r = page(`export default async function handle(req, res) {
      const body = JSON.parse(req.body);
      return res.json(await prisma.doc.findMany({ where: { userId: body.userId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("STILL does not count a verifier ARGUMENT that came from the request", () => {
    const r = page(`import { verifyLinkAccess } from "@/lib/links";
    export default async function handle(req, res) {
      const { viewerId, linkId } = req.query;
      const ok = await verifyLinkAccess(linkId);
      if (!ok) return res.status(403).end();
      return res.json(await prisma.view.findMany({ where: { viewerId } }));
    }`);
    expect(r.ownershipFiltered).toBe(false);
  });
});

// Two more shapes from the alias-resolution census, both wrong merge-check
// BLOCKS the moment their wrappers became readable.
describe("a token looked up in the database is a credential check we could not classify", () => {
  // corpus-a's /api/auth/reset-password finds the reset token by value and expiry.
  // MACHINE_GATE_RE has known the Supabase spelling `.eq("...token", …)` for a
  // long time; this is the Prisma spelling of the same check, and it lands in
  // the unclassified gap rather than as a gate, because a lookup whose result
  // nobody checks would silence a real finding.
  const route = (src: string) => collectRoutes([{ path: "app/api/x/route.ts", content: src }] as never)[0];

  it("prisma where: { token }", () => {
    const r = route(`export async function POST(req) {
      const { token, password } = await req.json();
      const found = await prisma.passwordResetToken.findFirst({ where: { token, expires: { gte: new Date() } }, select: { identifier: true } });
      if (!found) return new Response("invalid", { status: 400 });
      await prisma.user.update({ where: { email: found.identifier }, data: { password } });
      return Response.json({});
    }`);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/token|credential/i);
  });

  it("prisma where: { hashedKey } (corpus-b's API tokens)", () => {
    const r = route(`export async function POST(req) {
      const key = req.headers.get("x-api-key") ?? "";
      const t = await prisma.restrictedToken.findUnique({ where: { hashedKey: hash(key) }, select: { teamId: true } });
      if (!t) return new Response("no", { status: 401 });
      return Response.json(await prisma.document.findMany({ where: { teamId: t.teamId } }));
    }`);
    expect(r.identityReadable).toBe(false);
  });

  it("STILL calls a lookup by a plain id anonymous", () => {
    const r = route(`export async function GET(req) {
      const { id } = await req.json();
      return Response.json(await prisma.doc.findUnique({ where: { id } }));
    }`);
    expect(r.identityReadable).toBe(true);
  });
});

describe("a role check admits a caller across tenants by design", () => {
  // corpus-a's /api/admin/domains/renew is wrapped in withAdmin(), which resolves a
  // session and then requires a role. Read whole, that is "authenticated and
  // unscoped", and the merge check blocked it as an outlier on invoice. A
  // route admitted by role is not narrowed to one tenant on purpose, so the
  // scope is disclosed as unreadable rather than judged.
  const ADMIN = {
    path: "lib/auth/admin.ts",
    content: `import { getSession } from "./utils";
      export const withAdmin = (handler, { requiredRoles = [] } = {}) => async (req, { params }) => {
        const session = await getSession();
        if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
        const role = await getDubAdminRole(session.user.id);
        if (!role || (requiredRoles.length && !requiredRoles.includes(role))) return new Response("Forbidden", { status: 403 });
        return handler({ req, params, session });
      };`,
  };

  it("does not judge an admin route's scope", () => {
    const r = collectRoutes([
      { path: "app/api/admin/domains/renew/route.ts", content: `import { withAdmin } from "@/lib/auth/admin";
        export const POST = withAdmin(async ({ req }) => {
          const { domain } = await req.json();
          const d = await prisma.registeredDomain.findUnique({ where: { slug: domain } });
          await prisma.invoice.create({ data: { domainId: d.id } });
          return Response.json(d);
        });` },
      ADMIN,
    ] as never).find((x) => x.path === "/api/admin/domains/renew")!;
    expect(r.authenticated).toBe(true);
    expect(r.ownershipFiltered).toBe(false);
    expect(r.ownershipReadable).toBe(false);
    expect(r.ownershipGap).toMatch(/role/);
  });
});

// Provenance through one more hop, both found on corpus-a once wrappers resolved.
describe("an identity does not stop being the caller's when a function is applied to it", () => {
  const WRAPPER = {
    path: "lib/auth/workspace.ts",
    content: `import { getSession } from "./utils";
      export const withWorkspace = (handler) => async (req) => {
        const session = await getSession();
        if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
        const workspace = await prisma.project.findFirst({ where: { users: { some: { userId: session.user.id } } } });
        return handler({ req, workspace, session, searchParams: {} });
      };`,
  };
  const collect = (content: string) =>
    collectRoutes([{ path: "app/api/x/route.ts", content }, WRAPPER] as never).find((r) => r.path === "/api/x")!;

  it("KEEP where: { id: normalizeWorkspaceId(workspace.id) } (corpus-a ai/completion)", () => {
    const r = collect(`import { withWorkspace } from "@/lib/auth/workspace";
      export const POST = withWorkspace(async ({ workspace }) => {
        await prisma.project.update({ where: { id: normalizeWorkspaceId(workspace.id) }, data: { aiUsage: { increment: 1 } } });
        return Response.json({});
      });`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP a scope derived from the injected tenant: const programId = getDefaultProgramIdOrThrow(workspace) (corpus-a activity-logs)", () => {
    const r = collect(`import { withWorkspace } from "@/lib/auth/workspace";
      export const GET = withWorkspace(async ({ workspace, searchParams }) => {
        const programId = getDefaultProgramIdOrThrow(workspace);
        return Response.json(await prisma.activityLog.findMany({ where: { programId, action: searchParams.action } }));
      });`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("DROP an identity that is only logged", () => {
    const r = collect(`import { withWorkspace } from "@/lib/auth/workspace";
      export const GET = withWorkspace(async ({ workspace, searchParams }) => {
        console.log(workspace.id);
        return Response.json(await prisma.link.findUnique({ where: { id: searchParams.linkId } }));
      });`);
    expect(r.ownershipFiltered).toBe(false);
  });
});

// Found on corpus-a's /api/partner-profile/programs/[programId]: the statement
// `getProgramEnrollmentOrThrow({ partnerId: partner.id, programId:
// params.programId })` was DELETED whole because it mentions `params`, and the
// real filter went with it. A request read in a statement neutralises the
// request read, never the statement.
describe("a request read does not erase the filter beside it", () => {
  it("KEEP a session filter in the same statement as a params read", () => {
    const r = collectRoutes([{ path: "app/api/x/[id]/route.ts", content: `import { getServerSession } from "next-auth";
      export async function GET(req, { params }) {
        const session = await getServerSession();
        const row = await prisma.doc.findFirst({ where: { id: params.id, ownerId: session.user.id } });
        return Response.json(row);
      }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(true);
  });

  it("STILL does not count the params value itself", () => {
    const r = collectRoutes([{ path: "app/api/x/[userId]/route.ts", content: `export async function GET(req, { params }) {
        const userId = params.userId;
        const rows = await prisma.doc.findMany({ where: { userId } });
        return Response.json(rows);
      }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(false);
  });
});

// corpus-e's status page keeps its anonymous routes under a route group the
// application itself names "(public)". Once accidental ownership evidence was
// removed, /[domain]/[locale]/llms.txt BLOCKED the merge check as anonymous --
// a public status page, which is what it is for. A directory the application
// names public is a stated intent, so the route is disclosed, not judged.
describe("a route the application files under (public) is public by its own layout", () => {
  it("is disclosed as by-design rather than judged anonymous", () => {
    const r = collectRoutes([{ path: "src/app/(status-page)/[domain]/(public)/llms.txt/route.ts", content: `export async function GET(req, { params }) {
      const { domain } = await params;
      return Response.json(await db.query.page.findFirst({ where: eq(page.slug, domain) }));
    }` }] as never)[0];
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(false);
    expect(r.identityGap).toMatch(/public/);
  });

  it("STILL calls the same route anonymous outside such a group", () => {
    const r = collectRoutes([{ path: "src/app/api/llms/route.ts", content: `export async function GET(req) {
      const domain = new URL(req.url).searchParams.get("d");
      return Response.json(await db.query.page.findFirst({ where: eq(page.slug, domain) }));
    }` }] as never)[0];
    expect(r.identityReadable).toBe(true);
  });
});

// THE FOURTH WORDLIST FAILURE. corpus-a's /partners.corpus-a.co/invoices/[payoutId]
// carried ownershipFiltered: false while genuinely checking
// `payout.partnerId !== partner.id` and returning "not authorized". The
// provenance machinery worked -- `partner` came from a session-resolving
// wrapper and was renamed to the traced marker -- and then the comparison rule
// threw the result away because it required BOTH operands to match a
// vocabulary list (user|owner|account|tenant|org|profile), and `partnerId` is
// a domain noun outside it.
//
// The rule, not the list: one operand carrying verified provenance is
// sufficient. The other may be named anything, because a row's ownership
// column is unbounded vocabulary -- partner, merchant, vendor, subscriber --
// and what makes the comparison an authorization check is that it is compared
// against THE CALLER, which tracing establishes and naming does not.
//
// The exclusion runs the other way and is the viewerId lesson: a comparison
// against a caller-supplied value is not an ownership check, so the marker for
// request-derived values disqualifies an operand on either side.
describe("a comparison against a traced identity is an ownership check, whatever the column is called", () => {
  const WRAPPER = {
    path: "lib/auth/partner.ts",
    content: `import { getSession } from "./utils";
      export const withPartnerProfile = (handler) => async (req, { params }) => {
        const session = await getSession();
        if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
        const partner = await prisma.partner.findFirst({ where: { users: { some: { userId: session.user.id } } } });
        return handler({ req, params, partner });
      };`,
  };
  const wrapped = (body: string) =>
    collectRoutes([{ path: "app/api/x/[id]/route.ts", content: `import { withPartnerProfile } from "@/lib/auth/partner";\n${body}` }, WRAPPER] as never)
      .find((r) => r.path === "/api/x/[id]")!;

  it("KEEP corpus-a invoices: payout.partnerId !== partner.id, fetch-then-compare", () => {
    const r = wrapped(`export const GET = withPartnerProfile(async ({ partner, params }) => {
      const payout = await prisma.payout.findUniqueOrThrow({ where: { id: params.payoutId } });
      if (payout.partnerId !== partner.id) {
        return new Response("You are not authorized to view this payout.", { status: 403 });
      }
      return Response.json(payout);
    });`);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP the same shape for nouns no wordlist would contain", () => {
    for (const col of ["merchantId", "vendorId", "subscriberId", "practitionerId", "landlordId"]) {
      const r = wrapped(`export const GET = withPartnerProfile(async ({ partner, params }) => {
        const row = await prisma.record.findUniqueOrThrow({ where: { id: params.id } });
        if (row.${col} !== partner.id) return new Response("no", { status: 403 });
        return Response.json(row);
      });`);
      expect(r.ownershipFiltered, `${col} must count`).toBe(true);
    }
  });

  it("KEEP with the operands the other way round", () => {
    const r = wrapped(`export const GET = withPartnerProfile(async ({ partner, params }) => {
      const row = await prisma.record.findUniqueOrThrow({ where: { id: params.id } });
      if (partner.id !== row.merchantId) return new Response("no", { status: 403 });
      return Response.json(row);
    });`);
    expect(r.ownershipFiltered).toBe(true);
  });

  // The viewerId lesson, running the other way.
  it("DROP a comparison against a caller-supplied value", () => {
    const r = collectRoutes([{ path: "pages/api/x.ts", content: `export default async function handler(req, res) {
      const { viewerId } = req.query;
      const view = await prisma.view.findUnique({ where: { id: req.query.id } });
      if (view.merchantId !== viewerId) return res.status(403).end();
      return res.json(view);
    }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(false);
  });

  it("DROP a comparison between two caller-supplied values", () => {
    const r = collectRoutes([{ path: "pages/api/x.ts", content: `export default async function handler(req, res) {
      const { viewerId, otherId } = req.query;
      if (viewerId !== otherId) return res.status(400).end();
      return res.json(await prisma.doc.findMany());
    }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(false);
  });

  it("STILL leaves a route with no comparison unscoped", () => {
    const r = wrapped(`export const GET = withPartnerProfile(async ({ params }) => {
      return Response.json(await prisma.record.findUniqueOrThrow({ where: { id: params.id } }));
    });`);
    expect(r.ownershipFiltered).toBe(false);
  });

  // The shape an earlier draft of the tightening broke. Pinned by name again.
  it("STILL counts .eq('user_id', user.userId)", () => {
    const r = collectRoutes([{ path: "app/api/y/route.ts", content: `export async function GET() {
      const user = await requireProUser();
      await admin.from('audit_runs').select('*').eq('user_id', user.userId);
      return Response.json({});
    }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(true);
  });
});

// A type assertion between the session and the id defeated every caller-identity
// pattern. `(session.user as CustomUser).id` appears in 185 corpus-b files;
// 199 routes carry the shape and 13 of them read as unscoped because of it.
describe("a type assertion does not hide the caller", () => {
  it("KEEP a where clause filtered by an asserted session id", () => {
    const r = collectRoutes([{ path: "pages/api/x.ts", content: `import { getServerSession } from "next-auth/next";
      export default async function handler(req, res) {
        const session = await getServerSession(req, res, authOptions);
        if (!session) return res.status(401).end();
        const rows = await prisma.doc.findMany({ where: { userId: (session.user as CustomUser).id } });
        return res.json(rows);
      }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(true);
  });

  it("KEEP the corpus-b ai/store/runs shape: membership list built from an asserted session id", () => {
    const r = collectRoutes([{ path: "app/api/ai/store/runs/[runId]/route.ts", content: `import { getServerSession } from "next-auth";
      export async function GET(req, { params }) {
        const session = await getServerSession(authOptions);
        if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        const userTeams = await prisma.userTeam.findMany({ where: { userId: (session.user as CustomUser).id }, select: { teamId: true } });
        const userTeamIds = userTeams.map((ut) => ut.teamId);
        const run = await runs.retrieve(params.runId);
        if (!run.teamId || !userTeamIds.includes(run.teamId)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        return NextResponse.json(run);
      }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(true);
  });

  // The assertion must not manufacture ownership out of a request read.
  it("DROP an assertion over a caller-supplied value", () => {
    const r = collectRoutes([{ path: "pages/api/x.ts", content: `export default async function handler(req, res) {
      const { userId } = req.body as { userId: string };
      return res.json(await prisma.doc.findMany({ where: { userId } }));
    }` }] as never)[0];
    expect(r.ownershipFiltered).toBe(false);
  });
});

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

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

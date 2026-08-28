import { describe, expect, it } from "vitest";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { detectStack } from "./stack";
import { extractTables } from "./schema";
import { buildPrompt } from "./attack";
import { guardHypotheses, type ReconIndex } from "./attackGuard";
import { buildFindings } from "./findings";

/**
 * The whole pipeline on a realistic repository, with the model's step supplied
 * rather than called.
 *
 * Every other test here covers one collector. This one asks the question that
 * matters: given a codebase with a real tenant-isolation bug in it, does the
 * chain end with a finding a founder can act on -- and does the same chain
 * refuse a hypothesis about the route that is written correctly?
 */

const REPO = [
  {
    path: "package.json",
    content: JSON.stringify({
      dependencies: { next: "15.0.0", "@clerk/nextjs": "^5.0.0", "drizzle-orm": "^0.44.0", stripe: "^17.0.0" },
    }),
  },
  {
    path: "db/schema.ts",
    content: `
      export const invoices = pgTable("invoices", { id: uuid("id"), workspaceId: uuid("workspace_id") });
      export const workspaces = pgTable("workspaces", { id: uuid("id") });
    `,
  },
  {
    // The bug: a user is resolved, but nothing narrows the row to them.
    path: "app/api/invoices/[id]/route.ts",
    content: `
      import { auth } from "@clerk/nextjs/server";
      import { db } from "@/db";
      export async function GET(req, { params }) {
        const { userId } = await auth();
        if (!userId) return new Response("Unauthorized", { status: 401 });
        const invoice = await db.query.invoices.findFirst({ where: eq(invoices.id, params.id) });
        return Response.json(invoice);
      }
    `,
  },
  {
    // The control: the same shape, scoped correctly.
    path: "app/api/workspaces/[id]/route.ts",
    content: `
      import { auth } from "@clerk/nextjs/server";
      import { db } from "@/db";
      export async function GET(req, { params }) {
        const { userId, orgId } = await auth();
        if (!userId) return new Response("Unauthorized", { status: 401 });
        const ws = await db.query.workspaces.findFirst({
          where: and(eq(workspaces.id, params.id), eq(workspaces.ownerId, userId)),
        });
        return Response.json(ws);
      }
    `,
  },
];

describe("the pipeline, end to end on a repository with a real bug", () => {
  const stack = detectStack(REPO);
  const routes = collectRoutes(REPO);
  const tables = extractTables(REPO);

  it("identifies the stack from the manifest and the imports", () => {
    expect(stack.tools.map((t) => t.name).sort()).toEqual(["Clerk", "Drizzle", "Next.js", "Stripe"]);
    expect(stack.authUnknown).toBe(false);
  });

  it("maps both routes and reads the schema", () => {
    expect(routes.map((r) => r.path).sort()).toEqual(["/api/invoices/[id]", "/api/workspaces/[id]"]);
    expect(tables).toEqual(["invoices", "workspaces"]);
  });

  it("tells the model which route is scoped and which is not", () => {
    const prompt = buildPrompt({ routes, stack, tables, files: REPO.map((f) => f.path) });
    expect(prompt).toContain("auth:Clerk");
    expect(prompt).toMatch(/\/api\/invoices\/\[id\].*unscoped/);
  });

  const recon: ReconIndex = {
    entries: new Set(routes.map((r) => r.path)),
    files: new Set(REPO.map((f) => f.path)),
    tables: new Set(tables),
  };

  it("admits a grounded hypothesis and produces an actionable finding", () => {
    const result = guardHypotheses(
      [
        {
          entry: "/api/invoices/[id]",
          attackClass: "missing_authorization",
          title: "Any signed-in user can read another workspace's invoices",
          consequence: "A valid account is enough to retrieve billing records belonging to other customers.",
          citedFiles: ["app/api/invoices/[id]/route.ts"],
          citedTables: ["invoices"],
        },
      ],
      recon,
    );

    expect(result.rejected).toEqual([]);

    const [finding] = buildFindings({
      admitted: result.admitted,
      deterministic: [],
      routes,
      stack,
      repositoryId: "r1",
      hasDatabase: false,
    });

    expect(finding.severity).toBe("CRITICAL");
    expect(finding.fixKind).toBe("pr");
    expect(finding.file).toBe("app/api/invoices/[id]/route.ts");
    // Corroborated, never proven: nothing was executed anywhere.
    expect(finding.confidence).toBe("corroborated");
    // The reasoning has to name the actual gap, not restate the title.
    expect(finding.claims.some((c) => /nothing narrows the result/i.test(c.claim))).toBe(true);
    expect(finding.claims.some((c) => c.origin === "stack" && /Clerk/.test(c.claim))).toBe(true);
  });

  it("refuses a hypothesis about a table the repository does not have", () => {
    // The failure that would destroy trust on contact: a confident finding
    // about payment_methods, which this application has never heard of.
    const result = guardHypotheses(
      [
        {
          entry: "/api/invoices/[id]",
          attackClass: "missing_authorization",
          title: "Payment methods are exposed",
          consequence: "Card details can be read by any account.",
          citedFiles: ["app/api/invoices/[id]/route.ts"],
          citedTables: ["payment_methods"],
        },
      ],
      recon,
    );

    expect(result.admitted).toEqual([]);
    expect(result.rejected[0].reason).toContain("payment_methods");
  });

  it("refuses a hypothesis pointing at a file that was never read", () => {
    const result = guardHypotheses(
      [
        {
          entry: "/api/workspaces/[id]",
          attackClass: "missing_authentication",
          title: "The admin route is open",
          consequence: "Anyone can reach it.",
          citedFiles: ["app/api/admin/route.ts"],
        },
      ],
      recon,
    );

    expect(result.admitted).toEqual([]);
    expect(result.rejected[0].reason).toContain("was not read in this run");
  });
});

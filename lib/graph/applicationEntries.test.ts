import { describe, expect, it } from "vitest";
import { applicationEntries } from "./applicationEntries";

// The audit and the offline evaluator read the same entries.
const f = (path: string, content: string) => ({ path, content });

describe("applicationEntries", () => {
  it("returns route handlers, entry server actions and tRPC procedures as one list", () => {
    const entries = applicationEntries([
      f("app/api/tags/route.ts", "export async function GET() { return prisma.tag.findMany({}); }"),
      f("lib/actions/open.ts", `"use server";\nexport async function lookup(email: string) { return prisma.user.findUnique({ where: { email } }); }`),
      f("ui/form.tsx", `"use client";\nimport { lookup } from "@/lib/actions/open";`),
      f("server/trpc.ts", "export const t = initTRPC.create();\nexport const router = t.router;\nexport const publicProcedure = t.procedure;"),
      f("server/routers/page.ts", `import { publicProcedure, router } from "../trpc";
export const pageRouter = router({ bySlug: publicProcedure.query(async ({ input }) => prisma.page.findFirst({ where: { slug: input } })) });`),
    ]);
    expect(entries.routes.map((r) => r.path).sort()).toEqual([
      "/api/tags", "action:lib/actions/open.ts#lookup", "trpc:server/routers/page.ts#bySlug",
    ]);
    expect(entries).toMatchObject({ actions: 1, procedures: 1 });
  });
});

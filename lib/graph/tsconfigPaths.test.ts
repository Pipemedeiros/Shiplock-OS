import { describe, expect, it } from "vitest";
import { resolveViaTsconfigPaths, isWorkspacePackageImport } from "./tsconfigPaths";
import { resolveImport } from "@/lib/deep/clientExposure";
import { collectRoutes } from "./routeInventory";

const files = (...entries: [string, string][]) => new Map(entries.map(([path, content]) => [path, { path, content }]));

describe("tsconfig paths in a workspace", () => {
  const repo = files(
    ["apps/web/tsconfig.json", `{\n  // comments and trailing commas, as shipped\n  "extends": "tsconfig/nextjs.json",\n  "compilerOptions": { "baseUrl": ".", "paths": { "@/lib/*": ["lib/*"], "@/ui/*": ["ui/*"], }, },\n}`],
    ["apps/web/lib/auth/index.ts", `export * from "./workspace";`],
    ["apps/web/lib/auth/workspace.ts", `import { getServerSession } from "next-auth";\nexport const withWorkspace = (h) => async (req) => { const session = await getServerSession(); if (!session) return new Response("no", { status: 401 }); return h({ req, session }); };`],
    ["apps/web/app/api/links/route.ts", `import { withWorkspace } from "@/lib/auth";\nexport const GET = withWorkspace(async ({ session }) => Response.json(await prisma.link.findMany({ where: { userId: session.user.id } })));`],
    ["apps/docs/tsconfig.json", `{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }`],
    ["apps/docs/src/lib/x.ts", `export const x = 1;`],
    ["packages/utils/package.json", `{ "name": "@acme/utils", "main": "./dist/index.mjs" }`],
    ["package.json", `{ "name": "acme-monorepo", "private": true }`],
  );

  it("maps @/lib/* through the nearest tsconfig's baseUrl", () => {
    expect(resolveViaTsconfigPaths("apps/web/app/api/links/route.ts", "@/lib/auth", repo)).toBe("apps/web/lib/auth/index.ts");
  });

  it("picks the nearest config, not the first", () => {
    expect(resolveViaTsconfigPaths("apps/docs/src/page.ts", "@/lib/x", repo)).toBe("apps/docs/src/lib/x.ts");
    expect(resolveViaTsconfigPaths("apps/web/app/api/links/route.ts", "@/lib/x", repo)).toBeNull();
  });

  it("returns null for a mapping that points at nothing we ingested", () => {
    expect(resolveViaTsconfigPaths("apps/web/app/api/links/route.ts", "@/ui/missing", repo)).toBeNull();
  });

  it("resolveImport falls through to it, after the single-app layout", () => {
    expect(resolveImport("apps/web/app/api/links/route.ts", "@/lib/auth", repo)).toBe("apps/web/lib/auth/index.ts");
  });

  it("corpus-a's shape end to end: the wrapper body is read, the route is authenticated", () => {
    const r = collectRoutes([...repo.values()] as never).find((x) => x.file === "apps/web/app/api/links/route.ts")!;
    expect(r.authenticated).toBe(true);
    expect(r.identityReadable).toBe(true);
    expect(r.ownershipFiltered).toBe(true);
    expect(r.tables).toEqual(["link"]);
  });

  it("knows which bare specifiers are workspace packages", () => {
    expect(isWorkspacePackageImport("@acme/utils", repo)).toBe(true);
    expect(isWorkspacePackageImport("@acme/utils/dates", repo)).toBe(true);
    expect(isWorkspacePackageImport("next-auth", repo)).toBe(false);
    expect(isWorkspacePackageImport("@/lib/auth", repo)).toBe(false);
  });
});

describe("without a tsconfig nothing changes", () => {
  it("corpus-b's single-app layout still resolves through the old prefixes", () => {
    const repo = files(["lib/auth.ts", `export const a = 1;`], ["app/api/x/route.ts", `import { a } from "@/lib/auth";`]);
    expect(resolveImport("app/api/x/route.ts", "@/lib/auth", repo)).toBe("lib/auth.ts");
    expect(resolveViaTsconfigPaths("app/api/x/route.ts", "@/lib/auth", repo)).toBeNull();
  });
});

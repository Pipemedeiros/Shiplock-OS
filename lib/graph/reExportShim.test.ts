import { describe, expect, it } from "vitest";
import { collectRoutes } from "./routeInventory";
import type { RepoFile } from "@/lib/deep/githubScan";

/**
 * A route file whose whole body is `export * from "…"`.
 *
 * corpus-a keeps sixteen of these: `app/api/(old)/projects/[slug]/links/route.ts` is
 * one line, `export * from "../../../../links/route"`, and the real handler at
 * `app/api/links/route.ts` is `export const GET = withWorkspace(...)`.
 *
 * `traceExecutedSources` returns null on the shim, because `handlerRoots` reads
 * the module's own export names and a star re-export names none. The route then
 * falls back to whole-file import reading, which reaches the target's queries —
 * so ownership and tables partly propagate — but not the wrapper body two hops
 * further out, where the session call lives.
 *
 * The result was `authenticated: false` with `identityReadable: TRUE`: not an
 * admitted unknown but a confident assertion that we read the route and found
 * no gate, about a handler that is `withWorkspace`-gated. That is the standing
 * invariant inverted. `AuthzFacts.rulesRead` draws the same line for database
 * policies, and `identityReadable` exists to draw it here.
 *
 * The rule this file pins: when the handler is defined in another module and we
 * could not follow it, identity is UNREADABLE. Not anonymous.
 */

const WRAPPER: RepoFile = {
  path: "lib/auth/workspace.ts",
  content: `
    import { getServerSession } from "next-auth";
    import { authOptions } from "./options";
    export const withWorkspace = (handler) => async (req, ctx) => {
      const session = await getServerSession(authOptions);
      if (!session?.user) return new Response("Unauthorized", { status: 401 });
      const workspace = await prisma.project.findUnique({ where: { slug: ctx.params.slug } });
      return handler({ req, session, workspace });
    };
  `,
};

/**
 * The barrel is load-bearing, not decoration. corpus-a's target imports
 * `withWorkspace` from `@/lib/auth`, which re-exports from `./workspace`. From
 * the direct route that is two hops (route -> lib/auth -> workspace) and lands
 * inside MAX_IMPORT_DEPTH; from the shim it is three, and the wrapper body
 * holding the session call falls out of budget. Import the wrapper directly and
 * the bug does not reproduce.
 */
const BARREL: RepoFile = {
  path: "lib/auth/index.ts",
  content: `export * from "./workspace";\n`,
};

const TARGET: RepoFile = {
  path: "app/api/links/route.ts",
  content: `
    import { withWorkspace } from "@/lib/auth";
    import { prisma } from "@/lib/prisma";
    export const GET = withWorkspace(async ({ workspace }) => {
      const links = await prisma.link.findMany({ where: { projectId: workspace.id } });
      return Response.json(links);
    });
  `,
};

const SHIM: RepoFile = {
  path: "app/api/projects/[slug]/links/route.ts",
  content: `export * from "../../../links/route";\n`,
};

const routeAt = (files: RepoFile[], path: string) => {
  const r = collectRoutes(files).find((x) => x.path === path);
  if (!r) throw new Error(`no route at ${path}; got ${collectRoutes(files).map((x) => x.path).join(", ")}`);
  return r;
};

describe("a handler reached only through a star re-export", () => {
  it("is never reported as anonymous", () => {
    const shim = routeAt([SHIM, TARGET, BARREL, WRAPPER], "/api/projects/[slug]/links");
    // The whole point. Either we followed the handler and saw its gate, or we
    // did not and must say so. What we must never do is assert BOTH that there
    // is no gate and that we read it.
    expect({ authenticated: shim.authenticated, identityReadable: shim.identityReadable })
      .not.toEqual({ authenticated: false, identityReadable: true });
    // Said the other way round, so the intent survives a refactor: an
    // unauthenticated verdict here must come with an admitted gap.
    if (!shim.authenticated && !shim.machineGated) expect(shim.identityReadable).toBe(false);
  });

  it("reports the gap in words that name the cause", () => {
    const shim = routeAt([SHIM, TARGET, BARREL, WRAPPER], "/api/projects/[slug]/links");
    if (shim.authenticated) return; // fine: identity propagated, nothing to disclose
    expect(shim.identityReadable).toBe(false);
    expect(shim.identityGap ?? "").toMatch(/re-export|another module|handler/i);
  });

  it("still reads the direct route correctly, so the fix is not a blanket downgrade", () => {
    const direct = routeAt([SHIM, TARGET, BARREL, WRAPPER], "/api/links");
    expect(direct.authenticated).toBe(true);
    expect(direct.identityReadable).toBe(true);
  });

  it("does not downgrade a route that declares its own handler", () => {
    const plain: RepoFile = {
      path: "app/api/open/route.ts",
      content: `
        import { prisma } from "@/lib/prisma";
        export async function GET() {
          const rows = await prisma.post.findMany({});
          return Response.json(rows);
        }
      `,
    };
    const r = routeAt([plain], "/api/open");
    // Genuinely anonymous, genuinely read: this is the finding the product
    // exists to make, and the fix must not silence it.
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });
});

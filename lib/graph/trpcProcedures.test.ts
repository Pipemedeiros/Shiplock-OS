import { describe, expect, it } from "vitest";
import { analyzeTrpcProcedures, trpcRoutes } from "./trpcProcedures";

// Step 7G-1: identity, tables and ownership for tRPC procedures. Synthetic
// fixtures modelled on the create-t3-app / tRPC v10+ idioms; no corpus labels.
const f = (path: string, content: string) => ({ path, content });
const trpc = f("server/trpc.ts", `import { initTRPC, TRPCError } from "@trpc/server";
export const t = initTRPC.context<Context>().create({});
export const createTRPCRouter = t.router;
const timing = t.middleware(async ({ next }) => { const r = await next(); console.log("t"); return r; });
export const publicProcedure = t.procedure.use(timing);
const enforceUserIsAuthed = t.middleware(async ({ ctx, next }) => {
  if (!ctx.session?.user?.id) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next({ ctx: { ...ctx, workspace: await loadWorkspace(ctx.session.user.id) } });
});
export const protectedProcedure = t.procedure.use(enforceUserIsAuthed);
export const requireUser = t.middleware(async ({ ctx, next }) => {
  if (!ctx.user) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next();
});`);
const byName = (facts: ReturnType<typeof analyzeTrpcProcedures>) => new Map(facts.map((p) => [p.name, p]));

describe("analyzeTrpcProcedures", () => {
  it("reads identity from the base procedure's middleware and ownership through ctx", () => {
    const facts = byName(analyzeTrpcProcedures([trpc, f("server/routers/monitor.ts", `import { z } from "zod";
import { createTRPCRouter, protectedProcedure, publicProcedure } from "../trpc";
export const monitorRouter = createTRPCRouter({
  delete: protectedProcedure.input(z.object({ id: z.number() })).mutation(async ({ ctx, input }) => {
    return prisma.monitor.delete({ where: { id: input.id, workspaceId: ctx.workspace.id } });
  }),
  bySlug: publicProcedure.input(z.string()).query(async ({ input }) => prisma.page.findMany({ where: { slug: input } })),
});`)]));
    expect(facts.get("delete")).toMatchObject({ file: "server/routers/monitor.ts", kind: "mutation", base: "protectedProcedure",
      identityReadable: true, authenticated: true, tables: ["monitor"], ownershipReadable: true, ownershipFiltered: true });
    expect(facts.get("bySlug")).toMatchObject({ kind: "query", identityReadable: true, authenticated: false,
      tables: ["page"], ownershipReadable: true, ownershipFiltered: false });
  });

  it("counts inline .use() middleware on the procedure itself", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/comments.ts", `import { publicProcedure, requireUser, createTRPCRouter } from "../trpc";
export const comments = createTRPCRouter({
  add: publicProcedure.use(requireUser).input(s).mutation(async ({ ctx, input }) =>
    prisma.comment.create({ data: { pollId: input.pollId, userId: ctx.user.id } })),
});`)]);
    expect(fact).toMatchObject({ name: "add", authenticated: true, identityReadable: true, tables: ["comment"] });
  });

  // CORPUS-5 agent path (2026-10-06): two sign-in checks read as "no sign-in",
  // which titled real signed-in IDORs "Anyone can call this". Both are now a
  // gate we could not follow: never claimed as present, never as absent.
  it("reads a middleware that refuses when a no-argument auth helper returns nothing as a gate we could not follow (corpus-aa)", () => {
    const [fact] = analyzeTrpcProcedures([f("trpc/init.ts", `import { initTRPC, TRPCError } from "@trpc/server";
const t = initTRPC.create();
export const createTRPCRouter = t.router;
export const protectedProcedure = t.procedure.use(async ({ ctx, next }) => {
  const session = await isAuthenticated();
  if (!session) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: "UNAUTHORIZED" });
  }
  return next({ ctx: { ...ctx, auth: session } });
});`), f("modules/documents/procedures.ts", `import { createTRPCRouter, protectedProcedure } from "../../trpc/init";
export const documents = createTRPCRouter({
  getAllByFolderId: protectedProcedure.input(s).query(async ({ input }) => db.select().from(documents).where(eq(documents.folderId, input.folderId))),
});`)]);
    expect(fact).toMatchObject({ authenticated: false, identityReadable: false });
    expect(fact.identityGap).toMatch(/isAuthenticated/);
  });

  it("reads a ctx method named must, require, ensure or assert in the resolver as a gate we could not follow (corpus-ab)", () => {
    const [fact] = analyzeTrpcProcedures([f("server/trpc.ts", `export const t = initTRPC.context<Context>().create();`),
      f("server/routers/userRouter.ts", `import { t } from "../trpc";
export const userRouter = t.router({
  delete: t.procedure.input(s).mutation(async ({ ctx, input }) => {
    ctx.auth.mustBeReallyUser();
    return ctx.prisma.user.delete({ where: { id: input.id } });
  }),
});`)]);
    expect(fact).toMatchObject({ authenticated: false, identityReadable: false });
    expect(fact.identityGap).toMatch(/mustBeReallyUser/);
  });

  it("does not read a guard that lets a missing user through as authentication", () => {
    // corpus-d's mutationSessionGuard shape: the throw is for a deleted user, and
    // a caller with no user at all passes straight to next().
    const [fact] = analyzeTrpcProcedures([f("server/trpc.ts", `export const t = initTRPC.create();
export const router = t.router;
const sessionGuard = t.middleware(async ({ ctx, type, next }) => {
  if (type !== "mutation" || !ctx.user) {
    return next();
  }
  const user = await prisma.user.findUnique({ where: { id: ctx.user.id } });
  if (!user) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next();
});
export const publicProcedure = t.procedure.use(sessionGuard);`),
    f("server/routers/p.ts", `import { publicProcedure, router } from "../trpc";
export const p = router({ remove: publicProcedure.mutation(async ({ input }) => prisma.comment.delete({ where: { id: input.id } })) });`)]);
    expect(fact).toMatchObject({ identityReadable: true, authenticated: false });
  });

  it("follows a default-imported procedure to middleware in another file", () => {
    const [fact] = analyzeTrpcProcedures([
      f("server/trpc.ts", "export const t = initTRPC.create();\nexport const router = t.router;\nexport const procedure = t.procedure;\nexport const middleware = t.middleware;"),
      f("server/middlewares/session.ts", `import { middleware } from "../trpc";
export const isAuthed = middleware(async ({ ctx, next }) => {
  const { user, session } = await getUserSession(ctx);
  if (!user || !session) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next({ ctx: { user, session } });
});`),
      f("server/procedures/authedProcedure.ts", `import { isAuthed } from "../middlewares/session";
import { procedure } from "../trpc";
const authedProcedure = procedure.use(isAuthed);
export default authedProcedure;`),
      f("server/routers/keys/_router.ts", `import authedProcedure from "../../procedures/authedProcedure";
import { router } from "../../trpc";
export const keysRouter = router({
  list: authedProcedure.query(async ({ ctx }) => prisma.apiKey.findMany({ where: { userId: ctx.user.id } })),
});`),
    ]);
    expect(fact).toMatchObject({ name: "list", base: "authedProcedure", identityReadable: true, authenticated: true,
      tables: ["apiKey"], ownershipFiltered: true });
  });

  it("says unreadable when the base procedure cannot be resolved, never anonymous", () => {
    const [fact] = analyzeTrpcProcedures([f("server/routers/x.ts", `import { router } from "./t";
import { weirdProcedure } from "some-package";
export const x = router({ drop: weirdProcedure.mutation(async ({ input }) => prisma.tag.delete({ where: { id: input } })) });`)]);
    expect(fact).toMatchObject({ identityReadable: false, authenticated: false, ownershipReadable: false });
    expect(fact.identityGap).toMatch(/weirdProcedure/);
  });

  it("says unreadable when an inline middleware cannot be resolved and nothing else authenticates", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/y.ts", `import { publicProcedure, createTRPCRouter } from "../trpc";
import { gate } from "gates-pkg";
export const y = createTRPCRouter({ go: publicProcedure.use(gate).mutation(async () => prisma.tag.deleteMany({ where: {} })) });`)]);
    expect(fact).toMatchObject({ identityReadable: false, authenticated: false });
  });

  it("does not claim 'not filtered' when identity is handed to a helper", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/z.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const z = createTRPCRouter({
  update: protectedProcedure.mutation(async ({ ctx, input }) => {
    await assertCanEdit(ctx.workspace, input.id);
    return prisma.page.update({ where: { id: input.id }, data: input });
  }),
  sync: protectedProcedure.mutation(async ({ ctx, input }) => syncTags({ ctx: toServiceCtx(ctx), input })),
});`)]);
    expect(fact).toMatchObject({ name: "sync", tables: [], ownershipReadable: false, ownershipGap: expect.stringMatching(/no table/) });
    const update = analyzeTrpcProcedures([trpc, f("server/routers/z.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const z = createTRPCRouter({ update: protectedProcedure.mutation(async ({ ctx, input }) => {
  await assertCanEdit(ctx.workspace, input.id);
  return prisma.page.update({ where: { id: input.id }, data: input });
}) });`)]);
    expect(update[0]).toMatchObject({ tables: ["page"], ownershipFiltered: false, ownershipReadable: false, ownershipGap: expect.stringMatching(/helper/) });
  });

  it("follows an alias of ctx identity handed to a helper", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/c.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const c = createTRPCRouter({ remove: protectedProcedure.mutation(async ({ ctx, input }) => {
  const actor = ctx.user;
  const comment = await prisma.comment.findUnique({ where: { id: input.id } });
  if (!(await hasPollAdminAccess(comment.pollId, actor.id))) throw new TRPCError({ code: "FORBIDDEN" });
  await prisma.comment.delete({ where: { id: input.id } });
}) });`)]);
    expect(fact).toMatchObject({ tables: ["comment"], ownershipFiltered: false, ownershipReadable: false, ownershipGap: expect.stringMatching(/helper/) });
    // Q14: the route fact customers' findings quote carries that reason, never null.
    const [route] = trpcRoutes([trpc, f("server/routers/c.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const c = createTRPCRouter({ remove: protectedProcedure.mutation(async ({ ctx, input }) => {
  if (!(await hasPollAdminAccess(input.id, ctx.user.id))) throw new TRPCError({ code: "FORBIDDEN" });
  await prisma.comment.delete({ where: { id: input.id } });
}) });`)]);
    expect(route).toMatchObject({ ownershipReadable: false, ownershipGap: expect.stringMatching(/helper/) });
  });

  it("reads a Drizzle where narrowed by ctx as filtered", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/d.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const d = createTRPCRouter({ get: protectedProcedure.query(async ({ ctx, input }) =>
  ctx.db.select().from(monitor).where(and(eq(monitor.id, input.id), eq(monitor.workspaceId, ctx.workspace.id)))) });`)]);
    expect(fact).toMatchObject({ tables: ["monitor"], ownershipFiltered: true, ownershipReadable: true });
  });

  it("reads ctx carried only into query-builder calls as not narrowing, not as a helper", () => {
    const [fact] = analyzeTrpcProcedures([trpc, f("server/routers/d.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const d = createTRPCRouter({ rename: protectedProcedure.mutation(async ({ ctx, input }) =>
  ctx.db.update(monitor).set({ name: input.name, updatedBy: ctx.user.id }).where(eq(monitor.id, input.id)).from(monitor)) });`)]);
    expect(fact).toMatchObject({ tables: ["monitor"], ownershipFiltered: false, ownershipReadable: true });
  });

  it("names procedures in nested routers by their dotted path", () => {
    const facts = analyzeTrpcProcedures([trpc, f("server/routers/polls.ts", `import { publicProcedure, createTRPCRouter } from "../trpc";
export const polls = createTRPCRouter({
  comments: createTRPCRouter({ list: publicProcedure.query(async () => []) }),
  get: publicProcedure.query(async () => null),
});`)]);
    expect(facts.map((p) => p.name).sort()).toEqual(["comments.list", "get"]);
  });

  it("ignores tests, node_modules and files that only define procedures", () => {
    expect(analyzeTrpcProcedures([trpc,
      f("server/routers/a.test.ts", `import { publicProcedure, createTRPCRouter } from "../trpc";\ncreateTRPCRouter({ a: publicProcedure.query(() => 1) });`),
      f("node_modules/x/r.ts", `createTRPCRouter({ a: publicProcedure.query(() => 1) });`),
    ])).toEqual([]);
  });
});

describe("trpcRoutes", () => {
  it("renders procedures as route facts the audit can rank and cite", () => {
    const [route] = trpcRoutes([trpc, f("server/routers/m.ts", `import { protectedProcedure, createTRPCRouter } from "../trpc";
export const m = createTRPCRouter({ remove: protectedProcedure.mutation(async ({ ctx, input }) =>
  prisma.monitor.delete({ where: { id: input.id, workspaceId: ctx.workspace.id } })) });`)]);
    expect(route).toMatchObject({ path: "trpc:server/routers/m.ts#remove", file: "server/routers/m.ts", methods: ["MUTATION"],
      tables: ["monitor"], authenticated: true, identityReadable: true, ownershipFiltered: true, machineGated: false });
    expect(route.via).toContain("server/trpc.ts");
  });
});

// Q26: a ctx condition whose branch throws TRPCError UNAUTHORIZED is a gate,
// whatever the condition's spelling. Shapes from CORPUS-3 (development data).
describe("tRPC gates by TRPCError semantics (Q26)", () => {
  const router = (base: string) => f("server/routers/r.ts", `import { ${base}, createTRPCRouter } from "../trpc";
export const r = createTRPCRouter({ remove: ${base}.mutation(async ({ input }) => prisma.form.delete({ where: { id: input.id } })) });`);

  it("reads optional chaining on ctx (hash's enforceUserIsAuthed)", () => {
    const [fact] = analyzeTrpcProcedures([f("server/trpc.ts", `export const t = initTRPC.create();
export const createTRPCRouter = t.router;
const enforceUserIsAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx?.session?.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({ ctx: { session: { ...ctx.session, user: ctx.session.user } } });
});
export const protectedProcedure = t.procedure.use(enforceUserIsAuthed);`), router("protectedProcedure")]);
    expect(fact).toMatchObject({ authenticated: true, identityReadable: true });
  });

  it("reads a predicate over ctx (corpus-ac's authProtectedProcedure)", () => {
    const [fact] = analyzeTrpcProcedures([f("server/trpc.ts", `export const t = initTRPC.create();
export const createTRPCRouter = t.router;
export const publicProcedure = t.procedure;
export const authProtectedProcedure = publicProcedure.use(({ ctx, next }) => {
  if (!isValidUserInCtx(ctx)) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "User not logged in",
    });
  }
  return next({ ctx: { ...ctx, userId: ctx.auth.userId } });
});`), router("authProtectedProcedure")]);
    expect(fact).toMatchObject({ authenticated: true, identityReadable: true });
  });

  it("does not read an UNAUTHORIZED thrown on caller input as a session gate", () => {
    const [fact] = analyzeTrpcProcedures([f("server/trpc.ts", `export const t = initTRPC.create();
export const createTRPCRouter = t.router;
export const tokenProcedure = t.procedure.use(({ ctx, input, next }) => {
  if ((input as any)?.token !== process.env.PUBLIC_TOKEN) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next();
});`), router("tokenProcedure")]);
    expect(fact).toMatchObject({ authenticated: false });
  });
});

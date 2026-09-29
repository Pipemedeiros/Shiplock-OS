import { describe, expect, it } from "vitest";
import { analyzeServerActions, serverActionRoutes } from "./serverActionFacts";

// Step 7E-2: identity, tables and ownership for entry server actions.
// Synthetic fixtures modelled on the next-safe-action pattern; no corpus labels.
const f = (path: string, content: string) => ({ path, content });
const safeAction = f("lib/actions/safe-action.ts", `import { createSafeActionClient } from "next-safe-action";
import { getSession } from "../auth";
export const actionClient = createSafeActionClient({});
export const authActionClient = actionClient.use(async ({ next, clientInput }) => {
  const session = await getSession();
  if (!session?.user.id) throw new Error("Unauthorized");
  const workspace = await prisma.project.findUnique({ where: { id: clientInput.workspaceId } });
  return next({ ctx: { user: session.user, workspace } });
});`);
const ui = (imports: string) => f("ui/form.tsx", `"use client";\n${imports}`);

describe("analyzeServerActions", () => {
  it("reads identity from the action client's middleware and ownership through ctx", () => {
    const [fact] = analyzeServerActions([safeAction,
      f("lib/actions/rename.ts", `"use server";\nimport { authActionClient } from "./safe-action";
export const renameTag = authActionClient.inputSchema(s).action(async ({ parsedInput, ctx }) => {
  const { workspace } = ctx;
  await prisma.tag.update({ where: { id: parsedInput.id, projectId: workspace.id }, data: { name: parsedInput.name } });
});`), ui('import { renameTag } from "@/lib/actions/rename";')]);
    expect(fact).toMatchObject({ file: "lib/actions/rename.ts", name: "renameTag", client: "authActionClient",
      identityReadable: true, authenticated: true, tables: ["tag"], ownershipReadable: true, ownershipFiltered: true });
  });

  it("reads an action on the unauthenticated base client as anonymous", () => {
    const [fact] = analyzeServerActions([safeAction,
      f("lib/actions/open.ts", `"use server";\nimport { actionClient } from "./safe-action";
export const lookup = actionClient.action(async ({ parsedInput }) => prisma.user.findUnique({ where: { email: parsedInput.email } }));`),
      ui('import { lookup } from "@/lib/actions/open";')]);
    expect(fact).toMatchObject({ client: "actionClient", identityReadable: true, authenticated: false, tables: ["user"], ownershipFiltered: false });
  });

  it("says unreadable when the client cannot be resolved, never anonymous", () => {
    const [fact] = analyzeServerActions([
      f("lib/actions/x.ts", `"use server";\nimport { weirdClient } from "some-package";\nexport const x = weirdClient.action(async () => prisma.tag.delete({ where: { id: "1" } }));`),
      ui('import { x } from "@/lib/actions/x";')]);
    expect(fact).toMatchObject({ identityReadable: false, authenticated: false });
    expect(fact.identityGap).toMatch(/weirdClient/);
  });

  it("reads a plain exported function's own session check", () => {
    const facts = analyzeServerActions([
      f("app/actions.ts", `"use server";
export async function saveNote(formData: FormData) {
  const session = await getServerSession();
  if (!session) throw new Error("no");
  await prisma.note.create({ data: { userId: session.user.id, text: String(formData.get("t")) } });
}
export async function publicPing() { await prisma.ping.create({ data: {} }); }`),
      ui('import { saveNote, publicPing } from "@/app/actions";')]);
    expect(facts.map((a) => [a.name, a.authenticated, a.identityReadable, a.tables])).toEqual([
      ["publicPing", false, true, ["ping"]], ["saveNote", true, true, ["note"]]]);
  });

  it("only analyzes entry points", () => {
    expect(analyzeServerActions([safeAction, f("lib/helpers/h.ts", `"use server";\nexport async function h() {}`)])).toEqual([]);
  });

  it("accepts a current-user loader with a refusal in client middleware, but not a loader alone", () => {
    const client = (guard: string) => f("lib/safe-action.ts", `import { createSafeActionClient } from "next-safe-action";
export const actionClient = createSafeActionClient({});
export const authActionClient = actionClient.use(async ({ next }) => {
  const user = await getCurrentUser();
  ${guard}
  return next({ ctx: { user } });
});`);
    const action = f("lib/actions/a.ts", `"use server";\nimport { authActionClient } from "../safe-action";
export const del = authActionClient.action(async ({ ctx }) => prisma.space.delete({ where: { id: "1", ownerId: ctx.user.id } }));`);
    const form = ui('import { del } from "@/lib/actions/a";');
    expect(analyzeServerActions([client("if (!user) throw new Error(\"Unauthorized\");"), action, form])[0]).toMatchObject({ authenticated: true, ownershipFiltered: true });
    expect(analyzeServerActions([client(""), action, form])[0]).toMatchObject({ authenticated: false });
  });
});

describe("ownership is read, never assumed (7E-3 fix)", () => {
  const act = (body: string) => [safeAction, f("lib/actions/a.ts", `"use server";\nimport { authActionClient } from "./safe-action";
export const go = authActionClient.action(async ({ parsedInput, ctx }) => { ${body} });`), ui('import { go } from "@/lib/actions/a";')];
  it("is unreadable when the action delegates to helpers we did not trace", () => {
    const [a] = analyzeServerActions(act("const link = await getLinkOrThrow({ linkId: parsedInput.id, workspaceId: ctx.workspace.id }); await prisma.link.update({ where: { id: link.id }, data: {} });"));
    expect(a).toMatchObject({ ownershipReadable: false, ownershipFiltered: false, ownershipGap: expect.stringMatching(/helper/) });
    const [b] = analyzeServerActions(act("await updateLinkForWorkspace(ctx.workspace, parsedInput);"));
    expect(b).toMatchObject({ tables: [], ownershipReadable: false, ownershipGap: expect.stringMatching(/no table/) });
  });
  it("is unreadable for a create with no where clause to judge", () => {
    const [a] = analyzeServerActions(act("await prisma.tag.create({ data: { name: parsedInput.name, projectId: ctx.workspace.id } });"));
    expect(a).toMatchObject({ tables: ["tag"], ownershipReadable: false, ownershipGap: expect.stringMatching(/no where clause/) });
    // Q14: the route fact customers' findings quote carries that reason, never null.
    const [route] = serverActionRoutes(act("await prisma.tag.create({ data: { name: parsedInput.name, projectId: ctx.workspace.id } });"));
    expect(route).toMatchObject({ ownershipReadable: false, ownershipGap: expect.stringMatching(/no where clause/) });
  });
});

describe("server actions as audit entries (7E-3)", () => {
  it("become route facts with an action path, so ranking and the guard judge them like routes", async () => {
    const { serverActionRoutes } = await import("./serverActionFacts");
    const routes = serverActionRoutes([safeAction,
      f("lib/actions/open.ts", `"use server";\nimport { actionClient } from "./safe-action";
export const lookup = actionClient.action(async ({ parsedInput }) => prisma.user.findUnique({ where: { email: parsedInput.email } }));`),
      ui('import { lookup } from "@/lib/actions/open";')]);
    expect(routes).toEqual([expect.objectContaining({ path: "action:lib/actions/open.ts#lookup", file: "lib/actions/open.ts", methods: ["ACTION"],
      tables: ["user"], authenticated: false, identityReadable: true, ownershipFiltered: false, ownershipReadable: true, machineGated: false })]);
  });

  it("reads an unfiltered where as unscoped when identity is not handed elsewhere", async () => {
    const { analyzeServerActions: run } = await import("./serverActionFacts");
    const [a] = run([safeAction, f("lib/actions/b.ts", `"use server";\nimport { authActionClient } from "./safe-action";
export const go = authActionClient.action(async ({ parsedInput }) => prisma.tag.delete({ where: { id: parsedInput.id } }));`), ui('import { go } from "@/lib/actions/b";')]);
    expect(a).toMatchObject({ ownershipReadable: true, ownershipFiltered: false });
  });
});

describe("actions read the same tables as routes (7H-2)", () => {
  const act = (body: string) => [safeAction, f("lib/actions/a.ts", `"use server";\nimport { authActionClient } from "./safe-action";
export const go = authActionClient.action(async ({ parsedInput, ctx }) => { ${body} });`), ui('import { go } from "@/lib/actions/a";')];
  it("reads a Drizzle write narrowed by ctx identity as filtered", () => {
    const [a] = analyzeServerActions(act("const { workspace } = ctx; await db.update(tag).set({ name: parsedInput.name }).where(and(eq(tag.id, parsedInput.id), eq(tag.projectId, workspace.id)));"));
    expect(a).toMatchObject({ tables: ["tag"], ownershipFiltered: true, ownershipReadable: true });
  });
  it("reads a Drizzle write narrowed only by input as readable and not filtered", () => {
    const [a] = analyzeServerActions(act("await db.delete(tag).where(eq(tag.id, parsedInput.id));"));
    expect(a).toMatchObject({ tables: ["tag"], ownershipFiltered: false, ownershipReadable: true });
  });
  it("reads a Prisma transaction client", () => {
    const [a] = analyzeServerActions(act("await prisma.$transaction(async (tx) => { await tx.tag.delete({ where: { id: parsedInput.id, projectId: ctx.workspace.id } }); });"));
    expect(a).toMatchObject({ tables: ["tag"], ownershipFiltered: true, ownershipReadable: true });
  });
});

// Q24: a plain action's identity is read on the path it runs, like a route's.
// Shapes from Q23's false findings (corpus-r19 checkAdmin, corpus-r20
// getAuthenticatedUserForAction, corpus-r18's cookie JWT); synthetic code.
describe("plain actions follow their calls (Q24)", () => {
  const ui2 = (name: string, file: string) => f("ui/q24.tsx", `"use client";\nimport { ${name} } from "@/${file.replace(/\.ts$/, "")}";`);

  it("credits a session resolved inside a local helper the action calls", () => {
    const [a] = analyzeServerActions([f("app/actions/admin.ts", `"use server";
import { auth } from "@/lib/auth";
async function checkAdmin() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user?.id) return { success: false };
  return { success: true };
}
export async function createUser(input: { email: string }) {
  const check = await checkAdmin();
  if (!check.success) return check;
  return prisma.user.create({ data: { email: input.email } });
}`), ui2("createUser", "app/actions/admin.ts")]);
    expect(a).toMatchObject({ name: "createUser", identityReadable: true, authenticated: true });
  });

  it("credits a session resolved inside an imported helper", () => {
    const [a] = analyzeServerActions([
      f("lib/server-action-auth.ts", `import { getServerSession } from "next-auth";
export async function getAuthenticatedUserForAction() { const s = await getServerSession(authOptions); return s?.user ?? null; }`),
      f("app/autoreply/actions.ts", `"use server";
import { getAuthenticatedUserForAction } from "@/lib/server-action-auth";
export async function getAutoReplies(sessionId: string) {
  const user = await getAuthenticatedUserForAction();
  if (!user) throw new Error("Unauthorized");
  return prisma.autoReply.findMany({ where: { sessionId } });
}`), ui2("getAutoReplies", "app/autoreply/actions.ts")]);
    expect(a).toMatchObject({ identityReadable: true, authenticated: true });
  });

  it("says unreadable when a helper on the path verifies a credential we cannot classify", () => {
    const [a] = analyzeServerActions([
      f("lib/jwt.ts", `import jwt from "jsonwebtoken";
export const verifyCookieToken = (token: string) => jwt.verify(token, process.env.JWT_SECRET!);`),
      f("app/actions/comments.ts", `"use server";
import { cookies } from "next/headers";
import { verifyCookieToken } from "@/lib/jwt";
export async function deleteComment(id: number) {
  const payload = verifyCookieToken((await cookies()).get("token")?.value ?? "");
  if (!payload) return "not signed in";
  return prisma.comment.delete({ where: { id } });
}`), ui2("deleteComment", "app/actions/comments.ts")]);
    expect(a).toMatchObject({ identityReadable: false, authenticated: false });
    expect(a.identityGap).toMatch(/verifyCookieToken|jwt|cookie/i);
  });

  it("still reads an action with no check as anonymous (a data helper is not a gate)", () => {
    const [a] = analyzeServerActions([
      f("lib/db.ts", `export const findPost = (id: string) => prisma.post.findUnique({ where: { id } });`),
      f("app/actions/posts.ts", `"use server";
import { findPost } from "@/lib/db";
export async function removePost(id: string) {
  const post = await findPost(id);
  if (!post) throw new Error("Not found");
  return prisma.post.delete({ where: { id } });
}`), ui2("removePost", "app/actions/posts.ts")]);
    expect(a).toMatchObject({ identityReadable: true, authenticated: false, tables: ["post"] });
  });

  it("still reads input validation alone as anonymous", () => {
    const [a] = analyzeServerActions([f("app/actions/signup.ts", `"use server";
const schema = z.object({ email: z.string() });
export async function join(input: unknown) {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new Error("Invalid input");
  return prisma.waitlist.create({ data: parsed.data });
}`), ui2("join", "app/actions/signup.ts")]);
    expect(a).toMatchObject({ identityReadable: true, authenticated: false });
  });
});

describe("admin-gated actions (Q24)", () => {
  it("reads an action that requires the admin role as admitted by role, scope unread", () => {
    const [a] = analyzeServerActions([f("src/features/admin/actions/add.ts", `"use server";
import { auth } from "@/lib/better-auth";
export async function addExercise(input: { sessionId: string }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (session?.user?.role !== UserRole.admin) throw new Error("Unauthorized");
  return prisma.programSessionExercise.create({ data: { sessionId: input.sessionId } });
}`), f("ui/admin.tsx", `"use client";\nimport { addExercise } from "@/src/features/admin/actions/add";`)]);
    expect(a).toMatchObject({ authenticated: true, ownershipReadable: false, ownershipFiltered: false });
    expect(a.ownershipGap).toMatch(/admitted by role/);
  });
});

// Q24 guard: a signed-in action that narrows only by input stays unscoped.
// (Sharing the route recogniser with actions was tried and reverted: it read
// this shape as scoped, a fail-open; class C of Q23 stays open.)
describe("action ownership stays judged on its own where clauses (Q24)", () => {
  const ui3 = (name: string, path: string) => f("ui/own.tsx", `"use client";\nimport { ${name} } from "@/${path.replace(/\.ts$/, "")}";`);
  it("keeps a signed-in action that narrows only by input unscoped", () => {
    const [a] = analyzeServerActions([f("app/actions/members.ts", `"use server";
export async function removeMember(input: { memberId: string }) {
  const session = await getServerSession();
  if (!session?.user?.id) return { success: false, error: "Unauthorized" };
  await prisma.workspaceMember.delete({ where: { id: input.memberId } });
}`), ui3("removeMember", "app/actions/members.ts")]);
    expect(a).toMatchObject({ authenticated: true, ownershipFiltered: false, ownershipReadable: true });
  });

});

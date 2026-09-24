import { describe, expect, it } from "vitest";
import { analyzeServerActions } from "./serverActionFacts";

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
    expect(a).toMatchObject({ ownershipReadable: false, ownershipFiltered: false });
    const [b] = analyzeServerActions(act("await updateLinkForWorkspace(ctx.workspace, parsedInput);"));
    expect(b).toMatchObject({ tables: [], ownershipReadable: false });
  });
  it("is unreadable for a create with no where clause to judge", () => {
    const [a] = analyzeServerActions(act("await prisma.tag.create({ data: { name: parsedInput.name, projectId: ctx.workspace.id } });"));
    expect(a).toMatchObject({ tables: ["tag"], ownershipReadable: false });
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

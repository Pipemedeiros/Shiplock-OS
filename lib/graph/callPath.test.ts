import { describe, expect, it } from "vitest";
import { traceExecutedSources } from "./callPath";
import { collectRoutes } from "./routeInventory";

/**
 * Per-call-path attribution. Every fixture is the shape of a real route from
 * the five audited repositories; the first is corpus-b's
 * /api/conversations/[[...conversations]] reduced to its bones.
 */

const byPath = (files: { path: string; content: string }[]) => new Map(files.map((f) => [f.path, f]));
const route = (files: { path: string; content: string }[], entry = files[0].path) =>
  collectRoutes(files as never).find((r) => r.file === entry)!;

describe("only the code the handler runs is evidence", () => {
  const SERVICE = {
    path: "ee/lib/api/messages/index.ts",
    content: `import prisma from "@/lib/prisma";
      export const messageService = {
        async addMessage({ conversationId, content, viewerId, userId }: { conversationId: string; content: string; viewerId?: string; userId?: string }) {
          if ((!viewerId && !userId) || (viewerId && userId)) throw new Error("one of");
          const message = await prisma.message.create({ data: { content, conversationId, viewerId, userId } });
          const isParticipant = message.conversation.participants.some((p) => p.viewerId === viewerId || p.userId === userId);
          if (!isParticipant) await prisma.conversationParticipant.create({ data: { conversationId, userId } });
          return message;
        },
        async getUnreadMessages(viewerId?: string, userId?: string) {
          return prisma.message.findMany({ where: { conversation: { participants: { some: { userId } } } } });
        },
      };`,
  };
  const DISPATCH = {
    path: "ee/api/conversations-route.ts",
    content: `import { messageService } from "../lib/api/messages";
      const routeHandlers = {
        "POST /messages": async (req, res) => {
          const { content, viewId, viewerId, conversationId } = req.body;
          const message = await messageService.addMessage({ conversationId, content, viewId, viewerId });
          return res.status(201).json(message);
        },
      };
      export async function handleRoute(req, res) {
        const handler = routeHandlers[\`\${req.method} /\${req.query.conversations.join("/")}\`];
        if (!handler) return res.status(404).json({ error: "not found" });
        return handler(req, res);
      }`,
  };
  const ENTRY = {
    path: "pages/api/conversations/[[...conversations]].ts",
    content: `import { handleRoute } from "@/ee/api/conversations-route";
      export default async function handler(req, res) { return handleRoute(req, res); }`,
  };

  it("corpus-b /api/conversations: the shared library's unexecuted filter is not this route's filter", () => {
    const r = route([ENTRY, DISPATCH, SERVICE]);
    expect(r.tables).toContain("message");
    expect(r.ownershipFiltered).toBe(false);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });

  it("the same library, called from a route that DOES pass the user, is a filter", () => {
    const TEAM = {
      path: "pages/api/teams/[teamId]/unread.ts",
      content: `import { getServerSession } from "next-auth";
        import { messageService } from "@/ee/lib/api/messages";
        export default async function handler(req, res) {
          const session = await getServerSession(req, res, authOptions);
          const userId = session.user.id;
          return res.json(await messageService.getUnreadMessages(undefined, userId));
        }`,
    };
    const r = route([TEAM, SERVICE]);
    expect(r.authenticated).toBe(true);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("renders the unexecuted method blank and the unsupplied parameter renamed", () => {
    const trace = traceExecutedSources(ENTRY, byPath([ENTRY, DISPATCH, SERVICE]))!;
    const service = trace.sources.find((s) => s.path === SERVICE.path)!;
    expect(service.src).not.toContain("some: { userId }");
    expect(service.src).toContain("unsuppliedArg");
    expect(service.src).not.toMatch(/data: \{ conversationId, userId \}/);
    expect(service.host).toBe(false);
  });
});

describe("a parameter no call site supplies is not a filter on this path", () => {
  it("positional: getUnread(viewerId) leaves userId undefined", () => {
    const r = route([
      {
        path: "pages/api/x.ts",
        content: `import { getUnread } from "@/lib/unread";
          export default async function handler(req, res) { const { viewerId } = req.query; return res.json(await getUnread(viewerId)); }`,
      },
      {
        path: "lib/unread.ts",
        content: `export async function getUnread(viewerId, userId) { return prisma.message.findMany({ where: { participants: { some: { userId } } } }); }`,
      },
    ]);
    expect(r.ownershipFiltered).toBe(false);
  });

  it("but a parameter with a default is always supplied", () => {
    const r = route([
      {
        path: "pages/api/x.ts",
        content: `import { getServerSession } from "next-auth";
          import { getUnread } from "@/lib/unread";
          export default async function handler(req, res) { const session = await getServerSession(); return res.json(await getUnread()); }`,
      },
      {
        path: "lib/unread.ts",
        content: `export async function getUnread(userId = currentUserId()) { return prisma.message.findMany({ where: { userId } }); }`,
      },
    ]);
    expect(r.ownershipFiltered).toBe(true);
  });

  it("and a spread argument means we cannot tell, so nothing is renamed", () => {
    const r = route([
      {
        path: "pages/api/x.ts",
        content: `import { getServerSession } from "next-auth";
          import { load } from "@/lib/load";
          export default async function handler(req, res) { const session = await getServerSession(); const scope = { userId: session.user.id }; return res.json(await load({ ...scope })); }`,
      },
      { path: "lib/load.ts", content: `export async function load({ userId }) { return prisma.doc.findMany({ where: { userId } }); }` },
    ]);
    expect(r.ownershipFiltered).toBe(true);
  });
});

describe("an unexecuted declaration is not evidence, name included", () => {
  it("corpus-b workflow-entry: a helper module that also exports verifyLinkSession() does not authenticate a route that only creates sessions", () => {
    const r = route([
      {
        path: "app/api/workflow-entry/route.ts",
        content: `import { createLinkSession } from "@/lib/auth/link-session";
          export async function POST(req) {
            const { linkId, email } = await req.json();
            const link = await prisma.link.findUnique({ where: { id: linkId } });
            await createLinkSession({ linkId, email });
            return Response.json(link);
          }`,
      },
      {
        path: "lib/auth/link-session.ts",
        content: `export async function createLinkSession({ linkId, email }) { await redis.set(linkId, email); return { token: "t" }; }
          export async function verifyLinkSession(req, linkId) { const s = await redis.get(linkId); if (!s) return null; return s; }`,
      },
    ]);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(true);
  });

  it("but the same helper, when the route CALLS the verifier, is a session check", () => {
    const r = route([
      {
        path: "app/api/workflow-entry/route.ts",
        content: `import { verifyLinkSession } from "@/lib/auth/link-session";
          export async function POST(req) {
            const { linkId } = await req.json();
            const session = await verifyLinkSession(req, linkId);
            if (!session) return new Response("Unauthorized", { status: 401 });
            return Response.json(await prisma.link.findUnique({ where: { id: linkId } }));
          }`,
      },
      {
        path: "lib/auth/link-session.ts",
        content: `export async function createLinkSession({ linkId, email }) { await redis.set(linkId, email); return { token: "t" }; }
          export async function verifyLinkSession(req, linkId) { const s = await redis.get(linkId); if (!s) return null; return s; }`,
      },
    ]);
    expect(r.authenticated).toBe(true);
  });
});

describe("the file that hosts the handler is the route", () => {
  const EE = {
    path: "ee/jobs/notify.ts",
    content: `import prisma from "@/lib/prisma";
      export default async function handle(req, res) {
        const token = req.headers.authorization?.split(" ")[1];
        if (token !== process.env.INTERNAL_API_KEY) return res.status(401).json({ message: "Unauthorized" });
        const { teamId } = req.body;
        return res.json(await prisma.userTeam.findMany({ where: { teamId } }));
      }`,
  };

  it("corpus-b jobs/*: `export { default } from` carries the gate and the tables", () => {
    const r = route([{ path: "pages/api/jobs/notify.ts", content: `export { default } from "@/ee/jobs/notify";` }, EE]);
    expect(r.machineGated).toBe(true);
    expect(r.tables).toEqual(["userTeam"]);
    expect(r.methods).toEqual(["ALL"]);
  });

  it("`import h from …; export default h` is the same route", () => {
    const r = route([
      { path: "pages/api/jobs/notify.ts", content: `import defaultHandler from "@/ee/jobs/notify";\nexport default defaultHandler;` },
      EE,
    ]);
    expect(r.machineGated).toBe(true);
    expect(r.tables).toEqual(["userTeam"]);
  });

  it("a helper the handler merely CALLS is still a helper: its machine gate is a witness, not the gate", () => {
    const r = route([
      {
        path: "pages/api/x.ts",
        content: `import { verifyInternal } from "@/lib/internal";
          export default async function handler(req, res) { await verifyInternal(req); return res.json(await prisma.job.findMany()); }`,
      },
      { path: "lib/internal.ts", content: `export async function verifyInternal(req) { if (req.headers.authorization !== process.env.INTERNAL_API_KEY) throw new Error("no"); }` },
    ]);
    expect(r.machineGated).toBe(false);
    expect(r.machineGateReadable).toBe(false);
    expect(r.identityReadable).toBe(false);
  });
});

describe("a wrapper is read from its body, not guessed from its name", () => {
  it("a local wrapper that resolves a session makes the route authenticated", () => {
    const r = route([
      {
        path: "app/api/links/route.ts",
        content: `import { withWorkspace } from "@/lib/auth";
          export const GET = withWorkspace(async ({ workspace }) => Response.json(await prisma.link.findMany({ where: { projectId: workspace.id } })));`,
      },
      {
        path: "lib/auth.ts",
        content: `import { getServerSession } from "next-auth";
          export const withWorkspace = (handler) => async (req, ctx) => {
            const session = await getServerSession();
            if (!session) return new Response("Unauthorized", { status: 401 });
            const workspace = await prisma.project.findFirst({ where: { users: { some: { userId: session.user.id } } } });
            return handler({ req, workspace, session });
          };`,
      },
    ]);
    expect(r.authenticated).toBe(true);
    expect(r.identityReadable).toBe(true);
    // The wrapper's own membership query is identity construction, not the route's data.
    expect(r.tables).toEqual(["link"]);
  });

  it("a wrapper we cannot read is still an unreadable gate, never anonymous", () => {
    const r = route([
      {
        path: "app/api/links/route.ts",
        content: `import { withWorkspace } from "@/lib/auth";
          export const GET = withWorkspace(async ({ workspace }) => Response.json(await prisma.link.findMany()));`,
      },
    ]);
    expect(r.authenticated).toBe(false);
    expect(r.identityReadable).toBe(false);
  });
});

describe("handler discovery", () => {
  it("reads methods from `export { handler as GET, handler as POST }` (corpus-a's SCIM route)", () => {
    const r = route([
      {
        path: "app/api/scim/route.ts",
        content: `const handler = async (req: Request) => Response.json(await prisma.projectUsers.findMany());
          export { handler as DELETE, handler as GET, handler as POST };`,
      },
    ]);
    expect(r.methods).toEqual(["DELETE", "GET", "POST"]);
    expect(r.tables).toEqual(["projectUsers"]);
  });

  it("follows a switch on req.method into local functions", () => {
    const r = route([
      {
        path: "pages/api/x.ts",
        content: `import { getServerSession } from "next-auth";
          export default async function handler(req, res) {
            if (req.method === "GET") return list(req, res);
            return res.status(405).end();
          }
          async function list(req, res) {
            const session = await getServerSession(req, res);
            return res.json(await prisma.doc.findMany({ where: { ownerId: session.user.id } }));
          }
          async function never(req, res) { return res.json(await prisma.secret.findMany()); }`,
      },
    ]);
    expect(r.authenticated).toBe(true);
    expect(r.ownershipFiltered).toBe(true);
    expect(r.tables).toEqual(["doc"]);
  });

  it("includes handlers registered at module level (Hono in a route file)", () => {
    const r = route([
      {
        path: "app/api/[[...route]]/route.ts",
        content: `import { Hono } from "hono";
          import { handle } from "hono/vercel";
          const app = new Hono();
          app.get("/monitors", async (c) => c.json(await db.query.monitor.findMany()));
          export const GET = handle(app);`,
      },
    ]);
    expect(r.tables).toEqual(["monitor"]);
  });

  it("falls back to whole-file attribution when no handler export exists", () => {
    const files = [
      { path: "pages/api/legacy.ts", content: `module.exports = async (req, res) => res.json(await prisma.doc.findMany());` },
    ];
    expect(traceExecutedSources(files[0], byPath(files))).toBeNull();
    expect(route(files).tables).toEqual(["doc"]);
  });
});

import { describe, expect, it } from "vitest";
import { middlewareGap, unrefusedMethods } from "./methodRefusal";

// R1b (2026-10-08): `authenticated` is route-wide and means "some handler here
// resolves the caller". Three of four planted sign-in holes kept it, because
// another method in the same file still refused anonymous callers, and the
// agent was told the route was signed in. This fact is per method and only
// lists a handler when we READ that nothing in it refuses an anonymous caller.
const none = () => null;

describe("unrefusedMethods", () => {
  it("lists the method that resolves the caller and never refuses, not the one that does", () => {
    const src = `export async function POST(req) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  return NextResponse.json(await prisma.feedback.create({ data: { userId: session.user.id } }));
}
export async function GET(req) {
  const session = await getServerSession(authOptions);
  const { searchParams } = new URL(req.url);
  return NextResponse.json(await prisma.feedback.findMany({ where: {} }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual(["GET"]);
  });

  it("follows a local identity helper that returns null rather than refusing", () => {
    const src = `async function getAdminUser() {
  const { userId } = await auth();
  if (!userId) return null;
  return prisma.user.findUnique({ where: { clerkUserId: userId } });
}
export async function GET() {
  const admin = await getAdminUser();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json(await prisma.adminAction.findMany({ where: { adminId: admin.id } }));
}
export async function DELETE(req) {
  const admin = await getAdminUser();
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 });
  await prisma.scheduledNotification.update({ where: { id }, data: {} });
  return NextResponse.json({ ok: true });
}
`;
    const body = (name: string) => (name === "getAdminUser" ? "const { userId } = await auth(); if (!userId) return null; return x;" : null);
    expect(unrefusedMethods(src, body)).toEqual(["DELETE"]);
  });

  it("counts an optional session whose access check is never consulted", () => {
    const src = `export async function POST(req) {
  const session = await getServerSession(authOptions);
  let userId;
  if (session) {
    userId = session.user.id;
  }
  const hasAccess = await validateChatAccess({ chatId, userId });
  const chat = await prisma.chat.findUnique({ where: { id: chatId } });
  if (!chat) return new Response("Not found", { status: 404 });
  const features = await getFeatureFlags({ teamId: chat.teamId });
  if (!features.ai) return new Response("AI features are not available for this team", { status: 403 });
  return Response.json(await prisma.message.create({ data: {} }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual(["POST"]);
    const flags = (n: string) => (n === "getFeatureFlags"
      ? 'const team = await prisma.team.findUnique({ where: { id: teamId }, select: { plan: true, role: true } }); return { ai: team.plan !== "free" };'
      : null);
    expect(unrefusedMethods(src, flags)).toEqual(["POST"]);
  });

  it("treats an access check that is consulted as a refusal", () => {
    const src = `export async function POST(req) {
  const session = await getServerSession(authOptions);
  const hasAccess = await validateChatAccess({ userId: session?.user?.id });
  if (!hasAccess) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.message.create({ data: {} }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("treats a dereference of the caller as a refusal (an anonymous call crashes)", () => {
    const src = `export async function GET() {
  const session = await auth();
  return Response.json(await prisma.note.findMany({ where: { ownerId: session.user.id } }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("does not treat an optional or guarded dereference as a refusal", () => {
    const src = `export async function GET() {
  const session = await auth();
  const id = session?.user?.id;
  const name = session ? session.user.name : "guest";
  return Response.json(await prisma.post.findMany({ where: { published: true } }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual(["GET"]);
  });

  it("treats a throwing call, a redirect, or a helper that refuses as a possible refusal", () => {
    const throwing = `export async function GET() {
  const user = await requireUser();
  return Response.json(await db.note.findMany());
}
`;
    const redirecting = `export async function GET() {
  const user = await currentUser();
  if (!user) redirect("/sign-in");
  return Response.json(await db.note.findMany());
}
`;
    const viaHelper = `export async function GET(req) {
  const session = await getSession();
  await assertAccess(req);
  return Response.json(await db.note.findMany());
}
`;
    const helperThatThrows = `export async function GET(req) {
  const session = await getSession();
  await gate(req);
  return Response.json(await db.note.findMany());
}
`;
    expect(unrefusedMethods(throwing, none)).toEqual([]);
    expect(unrefusedMethods(redirecting, none)).toEqual([]);
    expect(unrefusedMethods(viaHelper, none)).toEqual([]);
    expect(unrefusedMethods(helperThatThrows, (n) => (n === "gate" ? 'if (!ok) throw new Error("Unauthorized")' : null))).toEqual([]);
  });

  it("does not count a helper that throws for reasons other than the caller (corpus-b's sendMessage)", () => {
    const src = `export async function POST(req) {
  const session = await getServerSession(authOptions);
  const userId = session?.user?.id;
  const ids = await getFilteredIds({ chatId });
  return sendMessage({ chatId, userId, ids });
}
`;
    const bodies: Record<string, string> = {
      getFilteredIds: 'try { return await q(); } catch { throw new Error("Failed to get filtered files"); }',
      sendMessage: '// Security: if the user sent unauthorized IDs, drop them\nif (!ok) throw new Error("vector store missing");',
    };
    expect(unrefusedMethods(src, (n) => bodies[n] ?? null)).toEqual(["POST"]);
  });

  it("does not judge a request handed to a helper it cannot read", () => {
    const src = `export async function GET(req) {
  const session = await getSession();
  return handle(req);
}
`;
    expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("does not judge wrapped or re-exported handlers", () => {
    const wrapped = `export const GET = withAuth(async (req) => Response.json(await db.x.findMany()));
export const POST = async () => {
  const session = await auth();
  return Response.json(await db.x.create({ data: {} }));
};
`;
    expect(unrefusedMethods(wrapped, none)).toEqual(["POST"]);
    expect(unrefusedMethods(`export { handler as GET } from "./h";`, none)).toEqual([]);
  });

  it("treats any branch that answers 401 or unauthorized as a refusal, whatever it tested (census 2026-10-08)", () => {
    const neutralHelper = `export async function GET() {
  const userId = await uid("manageSecrets");
  if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json(await readRow(userId));
}
`;
    const tokenLookup = `export async function GET(request) {
  const apiToken = request.headers.get("x-token");
  const user = await db.query.users.findFirst({ where: eq(users.id, apiToken) });
  if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  return NextResponse.json({ user });
}
`;
    const cron = `export async function GET(request) {
  if (!isValidCronRequest(request)) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const session = await getSession();
  return NextResponse.json(await run());
}
`;
    for (const src of [neutralHelper, tokenLookup, cron]) expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("follows a context helper that resolves the caller and carries its own refusal", () => {
    const src = `export async function GET(request, context) {
  const access = await resolveOwnedJob(context);
  if (access.response) return access.response;
  return Response.json(await access.supabase.from("shares").select("id"));
}
`;
    const body = (n: string) => (n === "resolveOwnedJob" ? "const user = await getCurrentUser(); if (!user) return { response: authRequiredResponse() };" : null);
    expect(unrefusedMethods(src, body)).toEqual([]);
  });

  it("treats returning a sign-in helper's own answer as a possible refusal (corpus-c)", () => {
    const src = `export const GET = async () => {
  const apiKey = (await headers()).get("x-api-key");
  if (apiKey) return handleApiKeyAuthentication(apiKey);
  return handleSessionAuthentication();
};
`;
    expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("never lists a preflight or HEAD handler, which serves no data", () => {
    const src = `export async function OPTIONS() { return new Response(null, { status: 204 }); }
export async function HEAD() { return new Response(null); }
export async function POST() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.post.create({ data: {} }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual([]);
  });

  it("lists a method that resolves no one beside one that refuses", () => {
    const src = `export async function GET() {
  return Response.json(await prisma.post.findMany());
}
export async function POST() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.post.create({ data: {} }));
}
`;
    expect(unrefusedMethods(src, none)).toEqual(["GET"]);
  });
});

describe("middlewareGap", () => {
  const file = (path: string, content: string) => ({ path, content });

  it("names a middleware that runs on the path and checks the caller", () => {
    const clerk = file("proxy.ts", `export default clerkMiddleware(async (auth, req) => {
  const { userId } = await auth();
  if (pathname.startsWith("/api")) return NextResponse.next();
});
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
`);
    expect(middlewareGap("app/api/x/route.ts", "/api/x", [clerk])).toMatch(/proxy\.ts/);
  });

  it("ignores a middleware whose matcher excludes the path", () => {
    const dashboardOnly = file("src/proxy.ts", `export async function proxy(request) {
  const token = await getToken({ req: request });
  if (!token) return NextResponse.redirect(new URL("/login", request.url));
}
export const config = { matcher: ["/dashboard/:path*"] };
`);
    const notApi = file("middleware.ts", `export default async function middleware(req) { await getSession(); }
export const config = { matcher: ["/((?!api/|_next/|favicon.ico).*)"] };
`);
    expect(middlewareGap("src/app/api/feedback/route.ts", "/api/feedback", [dashboardOnly])).toBeNull();
    expect(middlewareGap("app/api/x/route.ts", "/api/x", [notApi])).toBeNull();
  });

  it("ignores a middleware that never checks the caller", () => {
    const headers = file("middleware.ts", "export function middleware(req) { return NextResponse.next(); }");
    expect(middlewareGap("app/api/x/route.ts", "/api/x", [headers])).toBeNull();
  });

  it("only reads the middleware of the route's own application", () => {
    const other = file("apps/admin/middleware.ts", "export default clerkMiddleware(async (auth) => { await auth.protect(); });");
    expect(middlewareGap("apps/web/app/api/x/route.ts", "/api/x", [other])).toBeNull();
    expect(middlewareGap("apps/admin/app/api/x/route.ts", "/api/x", [other])).toMatch(/middleware\.ts/);
  });
});

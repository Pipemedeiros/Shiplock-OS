import { describe, expect, it } from "vitest";
import { applyPlant, findPlants } from "./plant";

// R1 (Felipe 2026-10-07: "how are we measuring recall?"): recall needs holes
// whose truth is certain. A plant removes one real control from a route the
// audit reads as safe; the hole exists by construction, and the planter must
// never produce a broken file or a "hole" that only crashes the route.
const parses = (src: string) => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const ts = require("typescript") as typeof import("typescript");
  return (ts.transpileModule(src, { reportDiagnostics: true, fileName: "route.ts" }).diagnostics ?? []).length === 0;
};

describe("findPlants: removing a sign-in guard", () => {
  it("removes a 401 guard whose user is not used after it", () => {
    const src = `import { auth } from "@/auth";
import { prisma } from "@/lib/db";
export async function GET() {
  const session = await auth();
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  const rows = await prisma.invoice.findMany();
  return Response.json(rows);
}
`;
    const plants = findPlants(src);
    expect(plants).toHaveLength(1);
    expect(plants[0].operator).toBe("remove_auth_guard");
    expect(plants[0].attackClasses).toEqual(["missing_authentication", "missing_authorization"]);
    const out = applyPlant(src, plants[0]);
    expect(out).not.toContain("Unauthorized");
    expect(out).toContain("prisma.invoice.findMany()");
    expect(parses(out)).toBe(true);
  });

  it("refuses a guard whose user the handler reads afterwards (removing it only crashes the route)", () => {
    const src = `export async function GET() {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  return Response.json(await db.note.findMany({ where: { ownerId: session.user.id } }));
}
`;
    expect(findPlants(src).filter((p) => p.operator === "remove_auth_guard")).toEqual([]);
  });

  it("refuses a guard that is not a sign-in refusal", () => {
    const src = `export async function POST(req: Request) {
  const body = await req.json();
  if (!body) return Response.json({ error: "Bad request" }, { status: 400 });
  return Response.json(await db.item.create({ data: {} }));
}
`;
    expect(findPlants(src)).toEqual([]);
  });

  it("treats a pages/api default export as the handler, only when told the file is one", () => {
    const src = `export default async function handler(req, res) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  res.json(await prisma.invoice.findMany());
}
`;
    expect(findPlants(src)).toEqual([]);
    const [plant] = findPlants(src, { defaultExportHandles: true });
    expect(plant.operator).toBe("remove_auth_guard");
    expect(applyPlant(src, plant)).not.toContain("401");
  });

  it("refuses a not-found check, even one that says unauthorized", () => {
    const src = `export async function POST(req: Request) {
  const row = await prisma.session.findFirst({ where: { id: "x" } });
  if (!row) {
    return NextResponse.json({ error: "Session not found or unauthorized" }, { status: 404 });
  }
  return Response.json(await prisma.feedback.create({ data: {} }));
}
`;
    expect(findPlants(src).filter((p) => p.operator === "remove_auth_guard")).toEqual([]);
  });

  it("counts a removed guard as either sign-in class (an admin check is authorization)", () => {
    const src = `export async function PATCH() {
  const isAdmin = await getIsAdmin();
  if (!isAdmin) return new NextResponse("Unauthorized.", { status: 401 });
  return Response.json(await db.option.update({ where: { id: "1" }, data: {} }));
}
`;
    expect(findPlants(src)[0].attackClasses).toEqual(["missing_authentication", "missing_authorization"]);
  });

  it("ignores guards outside an exported HTTP handler", () => {
    const src = `async function helper() {
  const user = await getUser();
  if (!user) throw new Error("Unauthorized");
  return 1;
}
export async function GET() { return Response.json(await helper()); }
`;
    expect(findPlants(src)).toEqual([]);
  });
});

describe("findPlants: removing an owner filter", () => {
  it("removes a Prisma owner property from a where clause", () => {
    const src = `export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const doc = await prisma.document.findFirst({ where: { id: params.id, userId: session.user.id } });
  return Response.json(doc);
}
`;
    const plants = findPlants(src).filter((p) => p.operator === "remove_owner_scope");
    expect(plants).toHaveLength(1);
    expect(plants[0].attackClasses).toEqual(["missing_authorization"]);
    const out = applyPlant(src, plants[0]);
    expect(out).toContain("where: { id: params.id }");
    expect(out).toContain('status: 401');
    expect(parses(out)).toBe(true);
  });

  it("removes a Supabase .eq on the owner column", () => {
    const src = `export async function GET() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data } = await supabase
    .from("notes")
    .select("*")
    .eq("user_id", user.id);
  return NextResponse.json(data);
}
`;
    const plants = findPlants(src).filter((p) => p.operator === "remove_owner_scope");
    expect(plants).toHaveLength(1);
    const out = applyPlant(src, plants[0]);
    expect(out).toContain('.select("*");');
    expect(out).not.toContain("user_id");
    expect(parses(out)).toBe(true);
  });

  it("removes a Drizzle owner eq from an and()", () => {
    const src = `export async function DELETE(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await db.delete(posts).where(and(eq(posts.id, id), eq(posts.authorId, session.user.id)));
  return new Response(null, { status: 204 });
}
`;
    const plants = findPlants(src).filter((p) => p.operator === "remove_owner_scope");
    expect(plants).toHaveLength(1);
    const out = applyPlant(src, plants[0]);
    expect(out).toContain("where(and(eq(posts.id, id)))");
    expect(parses(out)).toBe(true);
  });

  it("accepts a bare userId only when the handler took it from the caller's identity", () => {
    const fromSession = `export async function GET() {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.note.findMany({ where: { userId } }));
}
`;
    const fromBody = `export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { userId } = await req.json();
  return Response.json(await prisma.note.findMany({ where: { userId } }));
}
`;
    expect(findPlants(fromSession).filter((p) => p.operator === "remove_owner_scope")).toHaveLength(1);
    expect(findPlants(fromBody).filter((p) => p.operator === "remove_owner_scope")).toEqual([]);
  });

  it("refuses an owner filter whose removal only breaks a single-row read", () => {
    const supabaseSingle = `export async function GET() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data } = await supabase.from("profiles").select("*").eq("user_id", user.id).single();
  return NextResponse.json(data);
}
`;
    const prismaSole = `export async function GET() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.profile.findFirst({ where: { userId: session.user.id } }));
}
`;
    expect(findPlants(supabaseSingle).filter((p) => p.operator === "remove_owner_scope")).toEqual([]);
    expect(findPlants(prismaSole).filter((p) => p.operator === "remove_owner_scope")).toEqual([]);
  });

  it("keeps an owner filter removal that leaves a single-row read by id (an IDOR)", () => {
    const src = `export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data } = await supabase.from("notes").select("*").eq("id", params.id).eq("user_id", user.id).single();
  return NextResponse.json(data);
}
`;
    expect(findPlants(src).filter((p) => p.operator === "remove_owner_scope")).toHaveLength(1);
  });

  it("refuses an owner filter that is not taken from the caller", () => {
    const src = `export async function GET(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.post.findMany({ where: { authorId: req.headers.get("x-author") } }));
}
`;
    expect(findPlants(src).filter((p) => p.operator === "remove_owner_scope")).toEqual([]);
  });
});

describe("applyPlant", () => {
  it("refuses when the recorded bytes are not where the plant says (a different archive)", () => {
    const src = `export async function GET() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await db.x.findMany());
}
`;
    const [plant] = findPlants(src);
    expect(() => applyPlant(src.replace("export", "export "), plant)).toThrow(/does not match/);
  });
});

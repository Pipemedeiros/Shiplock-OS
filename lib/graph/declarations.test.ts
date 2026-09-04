import { describe, expect, it } from "vitest";
import { blankDeclarations } from "./declarations";

describe("blankDeclarations", () => {
  it("preserves length and line breaks", () => {
    const src = `import { a } from "b";\ninterface X { userId: string }\nconst y = 1;\n`;
    const out = blankDeclarations(src);
    expect(out.length).toBe(src.length);
    expect(out.split("\n").length).toBe(src.split("\n").length);
    expect(out).toContain("const y = 1;");
  });

  it("blanks interface fields, type aliases and enums", () => {
    const out = blankDeclarations(`interface Job { userId: string }\ntype Args = { userId?: string };\nenum R { service_role }\nconst z = 2;`);
    expect(out).not.toMatch(/userId|service_role/);
    expect(out).toContain("const z = 2;");
  });

  it("blanks type annotations, assertions and type arguments but keeps the values", () => {
    const out = blankDeclarations(`const rows: Array<{ userId: string }> = fetch<Row>() as Row[];\nconst q = prisma.doc.findMany({ where: { ownerId: userId } });`);
    expect(out).not.toMatch(/userId: string|Row/);
    expect(out).toContain("where: { ownerId: userId }");
  });

  it("blanks a typeof query inside a type, so it is not a table read", () => {
    const out = blankDeclarations(`type Rows = Awaited<ReturnType<typeof prisma.user.findMany>>;\nconst x = 1;`);
    expect(out).not.toContain("prisma.user.findMany");
  });

  it("blanks parameter names and destructures, but not what the body does with them", () => {
    const out = blankDeclarations(`async function f({ teamId, userId }: { teamId: string; userId?: string }, extra) {\n  return prisma.team.findFirst({ where: { id: teamId, users: { some: { userId } } } });\n}`);
    expect(out).not.toMatch(/\{ teamId, userId \}/);
    expect(out).toContain("some: { userId }");
  });

  it("keeps a parameter default, which is a use", () => {
    const out = blankDeclarations(`function f(scope = ctx.userId) { return scope; }`);
    expect(out).toContain("ctx.userId");
  });

  it("blanks a select projection but not the where beside it", () => {
    const out = blankDeclarations(`prisma.m.findMany({ where: { teamId: id }, select: { userId: true, role: true } })`);
    expect(out).not.toContain("userId: true");
    expect(out).toContain("where: { teamId: id }");
  });

  it("keeps a where nested inside a select projection: that is a filter, not a column", () => {
    const out = blankDeclarations(`prisma.project.findUnique({ where: { id }, select: { plan: true, users: { where: { userId: session.user.id }, select: { role: true } } } })`);
    expect(out).toContain("where: { userId: session.user.id }");
    expect(out).not.toContain("plan: true");
    expect(out).not.toContain("role: true");
  });

  it("blanks imports, so an imported name is not a call", () => {
    const out = blankDeclarations(`import { getServerSession } from "next-auth";\nexport async function GET() { return 1; }`);
    expect(out).not.toContain("getServerSession");
    expect(out).toContain("export async function GET()");
  });

  it("does not blank a variable declared with a plain identifier", () => {
    const out = blankDeclarations(`const userId = session.user.id;`);
    expect(out).toContain("const userId = session.user.id;");
  });

  // `(session.user as CustomUser).id` is the corpus-b idiom -- 185 files --
  // and blanking only the type left `(session.user           ).id`, where the
  // parentheses exist SOLELY to scope a type that no longer exists. Every
  // pattern that looks for a caller identity was blind to it.
  it("erases a parenthesised type assertion, parentheses included", () => {
    const out = blankDeclarations(`const userId = (session.user as CustomUser).id;`);
    expect(out).toMatch(/session\.user\s*\.\s*id/);
    expect(out).not.toContain("CustomUser");
    expect(out.length).toBe(`const userId = (session.user as CustomUser).id;`.length);
  });

  it("does the same for satisfies", () => {
    expect(blankDeclarations(`const t = (session.user satisfies U).id;`)).toMatch(/session\.user\s*\.\s*id/);
  });

  it("keeps parentheses that are not holding a type", () => {
    const src = `const x = (a || b).c; const y = (await f()).id;`;
    const out = blankDeclarations(src);
    expect(out).toContain("(a || b).c");
    expect(out).toContain("(await f()).id");
  });

  it("returns broken source unchanged in length rather than throwing", () => {
    const src = `export async function GET( { const x = ; }}}}`;
    expect(() => blankDeclarations(src)).not.toThrow();
    expect(blankDeclarations(src).length).toBe(src.length);
  });

  it("parses JSX in a .tsx file without blanking the markup", () => {
    const out = blankDeclarations(`export default function P({ userId }: { userId: string }) { return <div>{userId}</div>; }`, "x.tsx");
    expect(out).toContain("<div>{userId}</div>");
  });
});

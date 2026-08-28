import { describe, expect, it } from "vitest";
import { identifiersIn, isParseable, judgeEdit, syntaxErrorCount } from "./editGuard";

const ROUTE = `export async function GET(req, { params }) {
  const { userId, orgId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  const invoice = await db.query.invoices.findFirst({
    where: eq(invoices.id, params.id),
  });
  return Response.json(invoice);
}`;

describe("judgeEdit", () => {
  it("accepts a bounded change that parses and invents nothing", () => {
    const after = ROUTE.replace(
      "where: eq(invoices.id, params.id),",
      "where: and(eq(invoices.id, params.id), eq(invoices.orgId, orgId)),",
    ).replace("const { userId, orgId } = await auth();", "const { userId, orgId } = await auth();\n  const and = undefined;");
    const verdict = judgeEdit("route.ts", ROUTE, after);
    expect(verdict.safe).toBe(true);
  });

  it("refuses a change that does not parse", () => {
    // The failure that destroys trust on contact: the author opens the pull
    // request, sees a syntax error, and never opens another one.
    const verdict = judgeEdit("route.ts", ROUTE, ROUTE.replace("return Response.json(invoice);", "return Response.json(invoice;"));
    expect(verdict).toMatchObject({ safe: false, reason: "does_not_parse" });
  });

  it("refuses a change that references a symbol the file does not have", () => {
    // It parses perfectly and fails to compile in the customer's repository,
    // because `and` was never imported. Parsing is not enough.
    const after = ROUTE.replace(
      "where: eq(invoices.id, params.id),",
      "where: and(eq(invoices.id, params.id), eq(invoices.orgId, orgId)),",
    );
    const verdict = judgeEdit("route.ts", ROUTE, after);
    expect(verdict).toMatchObject({ safe: false, reason: "unknown_identifier" });
    if (!verdict.safe) expect(verdict.detail).toContain("and");
  });

  it("refuses a rewrite", () => {
    const verdict = judgeEdit("route.ts", ROUTE, "export async function GET() { return new Response('rewritten entirely by a machine'); }");
    expect(verdict.safe).toBe(false);
  });

  it("refuses a no-op rather than opening an empty pull request", () => {
    expect(judgeEdit("route.ts", ROUTE, ROUTE)).toMatchObject({ safe: false, reason: "unchanged" });
  });

  it("does not punish an edit to a file that was already broken", () => {
    // If the original does not parse, our change is not what broke it.
    const broken = "export async function GET( { return 1;";
    const after = broken + "\n// note";
    const verdict = judgeEdit("route.ts", broken, after);
    expect(verdict.safe).toBe(true);
  });

  it("parses TSX rather than reading the tags as syntax errors", () => {
    const before = "export const C = () => <div>{items.map((i) => i)}</div>;";
    expect(syntaxErrorCount("C.tsx", before)).toBe(0);
    expect(syntaxErrorCount("route.ts", "export async function GET( { return 1;")).toBeGreaterThan(0);
  });

  it("treats a whitespace-only change as nothing to open a pull request about", () => {
    const before = "export const C = () => <div>{items.map((i) => i)}</div>;";
    expect(judgeEdit("C.tsx", before, before + "\n")).toMatchObject({ safe: false, reason: "unchanged" });
  });

  it("allows an identifier the change itself declares", () => {
    // `and` introduced by a new import or a new const is fine; `and` merely
    // CALLED is the bug. Both add the identifier, only one fails to compile.
    const before = "export function f(a) { return g(a); }";
    const after = "import { and } from \"drizzle-orm\";\nexport function f(a) { return and(g(a)); }";
    expect(judgeEdit("f.ts", before, after).safe).toBe(true);
  });

  it("refuses a language it cannot parse rather than guessing", () => {
    // Handed a .py the TypeScript parser still returns a verdict, and that
    // verdict is noise wearing the costume of a check.
    const verdict = judgeEdit("migrate.py", "def f():\n    return 1\n", "def f():\n    return 2\n");
    expect(verdict).toMatchObject({ safe: false, reason: "unsupported_language" });
  });

  it("allows ambient globals without an import", () => {
    const before = "export function f() { return 1; }";
    const after = "export function f() { return JSON.stringify({ ok: true }); }";
    expect(judgeEdit("f.ts", before, after).safe).toBe(true);
  });
});

describe("identifiersIn", () => {
  it("collects the names a file already knows", () => {
    const names = identifiersIn("route.ts", ROUTE);
    expect(names.has("auth")).toBe(true);
    expect(names.has("invoices")).toBe(true);
    expect(names.has("and")).toBe(false);
  });
});

describe("failing closed", () => {
  it("knows the internal diagnostics field it depends on still exists", () => {
    // syntaxErrorCount reads TypeScript's internal `parseDiagnostics`. If a
    // version renames it, the guard must return null and refuse — never a
    // cheerful zero. This test is the tripwire for that rename.
    expect(syntaxErrorCount("route.ts", "const a = 1;")).not.toBeNull();
  });

  it("only claims to parse the languages it can", () => {
    for (const ok of ["a.ts", "a.tsx", "a.js", "a.jsx", "a.mjs", "a.cjs", "a.mts", "a.cts"]) {
      expect(isParseable(ok)).toBe(true);
    }
    for (const no of ["a.py", "a.sql", "a.rb", "a.go", "a.json", "Dockerfile", "a.yml"]) {
      expect(isParseable(no)).toBe(false);
    }
  });
});

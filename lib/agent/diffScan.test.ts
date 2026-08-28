import { describe, expect, it } from "vitest";
import { checkSummary, scanDiff, siblingsScopingTable } from "./diffScan";
import { collectRoutes } from "@/lib/graph/routeInventory";
import type { StackReport } from "./stack";

const stack: StackReport = { tools: [], authUnknown: false, databaseUnknown: false };

const scopedRoute = (path: string, table: string) => ({
  path,
  content: `
    export async function GET(req) {
      const { data: { user } } = await supabase.auth.getUser();
      return supabase.from("${table}").select("*").eq("user_id", user.id);
    }`,
});

const unscopedRoute = (path: string, table: string) => ({
  path,
  content: `
    export async function GET(req) {
      const { data: { user } } = await supabase.auth.getUser();
      return supabase.from("${table}").select("*");
    }`,
});

const anonRoute = (path: string, table: string) => ({
  path,
  content: `export async function GET(req) { return supabase.from("${table}").select("*") }`,
});

describe("scanDiff — the per-pull-request pass", () => {
  it("passes a documentation-only change without reading anything", () => {
    const result = scanDiff({ changed: [{ path: "README.md", content: "# hi" }], baseline: [], stack });
    expect(result.trivial).toBe(true);
    expect(result.verdict).toBe("pass");
  });

  it("blocks an anonymous route that reaches a table", () => {
    const result = scanDiff({
      changed: [anonRoute("app/api/invoices/route.ts", "invoices")],
      baseline: [],
      stack,
    });
    expect(result.verdict).toBe("block");
    expect(result.findings[0].title).toContain("without resolving a caller");
  });

  it("blocks an unscoped route when its siblings all scope the same table", () => {
    // The argument that makes a finding persuasive rather than an opinion.
    const result = scanDiff({
      changed: [unscopedRoute("app/api/invoices/[id]/route.ts", "invoices")],
      baseline: [
        scopedRoute("app/api/invoices/route.ts", "invoices"),
        scopedRoute("app/api/invoices/recent/route.ts", "invoices"),
      ],
      stack,
    });
    expect(result.verdict).toBe("block");
    expect(result.findings[0].evidence).toMatch(/2 of the 3 routes touching invoices filter by owner/);
  });

  it("only warns when nothing else scopes that table either", () => {
    // One unscoped route among unscoped routes may be a deliberate design. We
    // say so rather than blocking a merge on a guess.
    const result = scanDiff({
      changed: [unscopedRoute("app/api/posts/[id]/route.ts", "posts")],
      baseline: [unscopedRoute("app/api/posts/route.ts", "posts")],
      stack,
    });
    expect(result.verdict).toBe("warn");
    expect(result.findings[0].evidence).toMatch(/may be deliberate/);
  });

  it("ignores a machine-gated route, where a shared secret is the gate", () => {
    const result = scanDiff({
      changed: [{
        path: "app/api/cron/route.ts",
        content: `export async function GET(req){
          if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response("no", { status: 401 });
          return supabase.from("invoices").select();
        }`,
      }],
      baseline: [],
      stack,
    });
    expect(result.verdict).toBe("pass");
  });

  it("ignores a route that reaches no data at all", () => {
    const result = scanDiff({
      changed: [{ path: "app/api/health/route.ts", content: "export async function GET(){ return Response.json({ ok: true }) }" }],
      baseline: [],
      stack,
    });
    expect(result.verdict).toBe("pass");
  });

  it("blocks on a credential in the diff regardless of anything else", () => {
    const result = scanDiff({
      changed: [{ path: "lib/config.ts", content: 'export const k = "sb_secret_abcdef1234567890";' }],
      baseline: [],
      stack,
    });
    expect(result.verdict).toBe("block");
  });
});

describe("siblingsScopingTable", () => {
  it("counts how many routes touching a table filter by owner", () => {
    const routes = collectRoutes([
      scopedRoute("app/api/a/route.ts", "orders"),
      scopedRoute("app/api/b/route.ts", "orders"),
      unscopedRoute("app/api/c/route.ts", "orders"),
    ]);
    expect(siblingsScopingTable(routes, "orders")).toEqual({ scoped: 2, total: 3 });
  });
});

describe("checkSummary", () => {
  it("never says a clean pull request is safe", () => {
    // The most dangerous sentence this product could write. A check that found
    // nothing has found nothing; it has not certified anything.
    const { summary } = checkSummary({ verdict: "pass", findings: [], filesChanged: 4, routesChanged: 1, trivial: false });
    expect(summary).toMatch(/not a statement that the pull request is safe/i);
    expect(summary).not.toMatch(/\bsecure\b|\bsafe to merge\b/i);
  });

  it("gives each finding its evidence, so the author can disagree with it", () => {
    const { summary } = checkSummary({
      verdict: "block",
      findings: [{
        id: "x", severity: "CRITICAL", title: "T", detail: "D", file: "app/api/x/route.ts", evidence: "E",
      }],
      filesChanged: 1, routesChanged: 1, trivial: false,
    });
    expect(summary).toContain("E");
    expect(summary).toContain("app/api/x/route.ts");
  });
});

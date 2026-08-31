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

describe("a diff does not contain the auth helper", () => {
  // The first real pull request this check ran on posted "anyone on the
  // internet can call this endpoint" about a route whose first line is
  // requireProUser(), and BLOCKED the merge on it. Route facts follow imports
  // two hops to find the auth helper, and a pull request does not contain
  // lib/deep/proGate.ts, so every authenticated route in a diff read as
  // anonymous. A blocking verdict with a wrong reason is worse than no check.
  const helper = {
    path: "lib/deep/proGate.ts",
    content: `import { getSupabaseServer } from "@/lib/supabaseServer";
      export async function requireProUser() {
        const supabase = await getSupabaseServer();
        const { data: { user } } = await supabase.auth.getUser();
        return user ? { userId: user.id } : null;
      }`,
  };

  const changedRoute = {
    path: "app/api/scan-history/[id]/route.ts",
    content: `import { requireProUser } from "@/lib/deep/proGate";
      import { getSupabaseAdmin } from "@/lib/supabase";
      export async function GET(_req, context) {
        const user = await requireProUser();
        if (!user) return Response.json({ error: "Not signed in." }, { status: 401 });
        const { id } = await context.params;
        const { data } = await getSupabaseAdmin().from("scan_history").select("*").eq("id", id).single();
        return Response.json({ scan: data });
      }`,
  };

  it("does not call an authenticated route anonymous", () => {
    const result = scanDiff({
      changed: [changedRoute],
      baseline: [helper],
      stack: { tools: [], authUnknown: false, databaseUnknown: false },
    });

    const anon = result.findings.filter((f) => f.id.startsWith("diff:anon:"));
    expect(anon, anon[0]?.title).toHaveLength(0);
  });

  it("still reports a genuinely anonymous route", () => {
    const result = scanDiff({
      changed: [
        {
          path: "app/api/open/route.ts",
          content: `import { getSupabaseAdmin } from "@/lib/supabase";
            export async function GET() {
              const { data } = await getSupabaseAdmin().from("scan_history").select("*");
              return Response.json(data);
            }`,
        },
      ],
      baseline: [helper],
      stack: { tools: [], authUnknown: false, databaseUnknown: false },
    });
    expect(result.findings.some((f) => f.id.startsWith("diff:anon:"))).toBe(true);
  });
});

describe("edge cases found by adversarial testing", () => {
  const proGate = {
    path: "lib/deep/proGate.ts",
    content: `export async function requireProUser() {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return null;
      const { data } = await admin.from("user_profiles").select("is_paid").eq("id", user.id).single();
      return { userId: user.id }; }`,
  };
  const stack = { tools: [], authUnknown: false, databaseUnknown: false };
  const run = (changed: { path: string; content: string }[], baseline = [proGate]) =>
    scanDiff({ changed, baseline, stack });

  it("does not read a query written inside a string literal as data access", () => {
    // `const sample = "admin.from('orders').select('*')"` is documentation, a
    // code sample or a generator template. Reading it as a query reported an
    // endpoint that returns a constant as CRITICAL for exposing a table.
    const r = run([
      {
        path: "app/api/sample/route.ts",
        content: `const sample = "admin.from('orders').select('*')";
          export async function GET() { return Response.json({ sample }); }`,
      },
    ]);
    expect(r.findings).toEqual([]);
  });

  it("still reads a real query whose table name is a string", () => {
    // The obvious way to break the fix above: the table name in a genuine
    // `.from("orders")` is itself a string literal.
    const r = run([
      {
        path: "app/api/leak/route.ts",
        content: `export async function GET() { return Response.json(await admin.from("orders").select("*")); }`,
      },
    ]);
    expect(r.findings.some((f) => f.id.startsWith("diff:anon:"))).toBe(true);
  });

  it("never calls a route anonymous when it filters by the caller", () => {
    // The two cannot both be true. When they are, we failed to see the auth,
    // and reporting the contradiction as a blocking critical is the worst
    // outcome available.
    const r = run([
      {
        path: "app/api/deep/route.ts",
        content: `import { guard } from "@/lib/guard";
          export async function GET() { const c = await guard();
            return Response.json(await admin.from("orders").select("*").eq("user_id", c.userId)); }`,
      },
    ]);
    expect(r.findings.filter((f) => f.id.startsWith("diff:anon:"))).toEqual([]);
  });

  it("survives a file with a syntax error", () => {
    expect(() =>
      run([{ path: "app/api/broken/route.ts", content: `export async function GET( { return admin.from("orders")` }]),
    ).not.toThrow();
  });

  it("survives a very large file", () => {
    const big = "// filler\n".repeat(20000);
    const r = run([
      {
        path: "app/api/big/route.ts",
        content: big + `export async function GET() { return Response.json(await admin.from("orders").select("*")); }`,
      },
    ]);
    expect(r.findings.some((f) => f.id.startsWith("diff:anon:"))).toBe(true);
  });

  it("ignores a vulnerable route that exists only in a comment", () => {
    const r = run([
      {
        path: "app/api/commented/route.ts",
        content: `// export async function GET() { return Response.json(await admin.from("orders").select("*")); }
          export async function GET() { return Response.json({ ok: true }); }`,
      },
    ]);
    expect(r.findings).toEqual([]);
  });

  it("does not treat a hardcoded uuid as the caller", () => {
    const r = run([
      {
        path: "app/api/const/route.ts",
        content: `import { requireProUser } from "@/lib/deep/proGate";
          export async function GET() { await requireProUser();
            return Response.json(await admin.from("orders").select("*").eq("user_id", "11111111-2222-3333-4444-555555555555")); }`,
      },
    ]);
    expect(r.findings.some((f) => f.id.startsWith("diff:unscoped:"))).toBe(true);
  });
});

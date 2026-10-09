import { describe, expect, it } from "vitest";
import { summarizeEvaluation } from "./evaluation";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { guardHypotheses } from "./attackGuard";

describe("offline evaluation honesty", () => {
  it("keeps unknown recall null for an unlabeled repository", () => {
    const result = summarizeEvaluation([], new Set(), new Set(), new Set(), new Set());
    expect(result.candidateCoverage).toBeNull();
    expect(result.modelPrecision).toBeNull();
  });

  it("keeps missing positives in the denominator and names them", () => {
    const result = summarizeEvaluation([
      { route: "/one", verdict: "vulnerable" }, { route: "/missing", verdict: "vulnerable" },
    ], new Set(["/one"]), new Set(["/one"]), new Set(["/one"]), new Set());
    expect(result.candidateCoverage).toBe(0.5);
    expect(result.missingLabeledRoutes).toEqual(["/missing"]);
  });

  it("does not turn benign INFO rewording into a smaller precision denominator", () => {
    const result = summarizeEvaluation([
      { route: "/real", verdict: "vulnerable" }, { route: "/benign", verdict: "benign" },
    ], new Set(["/real", "/benign"]), new Set(["/real", "/benign"]),
    new Set(["/real", "/benign"]), new Set(["/benign"]));
    expect(result.labeledRoutes).toBe(2);
    expect(result.replayAdmittedFalse).toBe(1);
    expect(result.rewordedLabels).toBe(1);
    expect(result.modelPrecision).toBeNull();
  });

  it("distinguishes a known anonymous gap from its authenticated negative control", () => {
    const files = [
      { path: "app/api/open/route.ts", content: `export async function GET(){ return supabase.from("invoices").select("*") }` },
      { path: "app/api/guarded/route.ts", content: `export async function GET(){ const session = await getServerSession(); if(!session) return new Response("no", {status:401}); return supabase.from("invoices").select("*") }` },
    ];
    const routes = collectRoutes(files);
    const result = guardHypotheses(routes.map((route) => ({
      entry: route.path, attackClass: "missing_authentication", title: "Missing identity",
      consequence: "An anonymous caller can read invoices.", citedFiles: [route.file], citedTables: ["invoices"],
    })), {
      entries: new Set(routes.map((route) => route.path)), files: new Set(files.map((file) => file.path)),
      tables: new Set(["invoices"]), routes: new Map(routes.map((route) => [route.path, route])),
    });
    // The guarded route is never admitted as anonymous. Since R1 run 3 the
    // claim goes to verification as authorization (it reads every invoice
    // with no owner filter), under neutral wording.
    const asAnonymous = result.admitted.filter((h) => h.attackClass === "missing_authentication").map((h) => h.entry);
    expect(asAnonymous).toEqual(["/api/open"]);
    const guarded = result.admitted.find((h) => h.entry === "/api/guarded");
    expect(guarded).toMatchObject({ attackClass: "missing_authorization", title: "Any signed-in user may reach rows that are not theirs" });
    expect(result.rejected).toHaveLength(0);
  });
});

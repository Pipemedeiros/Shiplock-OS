import { describe, expect, it, vi } from "vitest";

// H1 regression: only getRuns reads intelligence tasks (to update each run's
// reasoning note). A slip once pasted that lookup into getRepositories and
// getRecentlyClosed, where it ran a useless query per call.
const tables: string[] = [];
let rows: unknown[] = [{ id: "r1", full_name: "acme/app", title: "t", archived_at: "2026-10-06T00:00:00Z" }];
const chain = (): unknown => new Proxy(() => {}, {
  get: (_t, key) => (key === "then" ? (resolve: (v: unknown) => void) => resolve({ data: rows, error: null }) : chain()),
  apply: () => chain(),
});
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => { tables.push(table); return chain(); } }) }));
vi.mock("react", async (orig) => ({ ...(await orig<typeof import("react")>()), cache: <T,>(fn: T) => fn }));
const data = await import("./dashboardData");

describe("dashboard reads", () => {
  it("getRepositories and getRecentlyClosed never read intelligence tasks", async () => {
    tables.length = 0;
    await data.getRepositories("u1");
    await data.getRecentlyClosed("u1");
    expect(tables).not.toContain("intelligence_tasks");
  });

  // A1 (Felipe 2026-10-07): each open finding says whether it is a confirmed
  // issue, and confirmed issues come first, whatever their severity.
  it("marks confirmed issues and lists them before candidates", async () => {
    const row = (id: string, severity: string, claims: unknown[], attack = "missing_authorization") =>
      ({ id, finding_id: id, title: id, consequence: "c", severity, confidence: "inferred", attack_class: attack, claims, detected_at: "2026-10-07T00:00:00Z" });
    rows = [row("candidate-critical", "CRITICAL", [{ claim: "x", origin: "routes", verified: true }]),
      row("proven-warning", "WARNING", [{ claim: "Proof, data: a.ts:2 q", origin: "agent", verified: true }])];
    const open = await data.getOpenFindings("u1");
    expect(open.map((f) => [f.id, f.confirmed])).toEqual([["proven-warning", true], ["candidate-critical", false]]);
  });
});

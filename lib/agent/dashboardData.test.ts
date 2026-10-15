import { describe, expect, it, vi } from "vitest";

// H1 regression: only getRuns reads intelligence tasks (to update each run's
// reasoning note). A slip once pasted that lookup into getRepositories and
// getRecentlyClosed, where it ran a useless query per call.
const tables: string[] = [];
let rows: unknown[] = [{ id: "r1", full_name: "acme/app", title: "t", archived_at: "2026-10-06T00:00:00Z" }];
const calls: { method: string; args: unknown[] }[] = [];
const chain = (method = ""): unknown => new Proxy(() => {}, {
  get: (_t, key) => (key === "then" ? (resolve: (v: unknown) => void) => resolve({ data: rows, error: null }) : chain(String(key))),
  apply: (_t, _this, args) => { calls.push({ method, args }); return chain(); },
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

  // A3: the attack feed reads the agent's tasks for the newest audit with any.
  it("loads the newest audit's attack tasks", async () => {
    tables.length = 0;
    rows = [{ id: "r", kind: "attack_reasoning", status: "pending", expires_at: null, result: null, context: {}, audit_run_id: "run1" }];
    const tasks = await data.getAttackTasks("u1");
    expect(tables).toContain("intelligence_tasks");
    expect(tasks.map((t) => t.kind)).toContain("attack_reasoning");
  });

  // W3: what ShipLock observed outside the repository reaches Issues and the
  // status, with the evidence each row rests on.
  it("reads live findings beside the agent's, and confirms a proof or an observed exposure", async () => {
    calls.length = 0;
    const live = (id: string, source: string, severity = "CRITICAL") =>
      ({ id, finding_id: id, source, title: id, consequence: "c", severity, confidence: null, attack_class: null, claims: null, detected_at: "2026-10-07T00:00:00Z" });
    rows = [live("proof:rls:orders", "proven"), live("bundle:shipped_secret:supabase_service_role_jwt", "exposed-path"),
      live("email_auth:dmarc_missing", "exposed-path", "WARNING")];
    const open = await data.getOpenFindings("u1");
    expect(calls).toContainEqual({ method: "in", args: ["source", ["agent", "proven", "policy", "postgres-direct", "exposed-path", "vercel", "runtime"]] });
    expect(open.map((f) => [f.id, f.confirmed, f.confidence])).toEqual([
      ["proof:rls:orders", true, "proven"],
      ["bundle:shipped_secret:supabase_service_role_jwt", true, "corroborated"],
      ["email_auth:dmarc_missing", false, "inferred"],
    ]);
    expect(open[1].claims[0]).toMatchObject({ origin: "live", verified: true });
  });
});


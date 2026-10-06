import { describe, expect, it, vi } from "vitest";

// H1 regression: only getRuns reads intelligence tasks (to update each run's
// reasoning note). A slip once pasted that lookup into getRepositories and
// getRecentlyClosed, where it ran a useless query per call.
const tables: string[] = [];
const chain = (): unknown => new Proxy(() => {}, {
  get: (_t, key) => (key === "then" ? (resolve: (v: unknown) => void) => resolve({ data: [{ id: "r1", full_name: "acme/app", title: "t", archived_at: "2026-10-06T00:00:00Z" }], error: null }) : chain()),
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
});

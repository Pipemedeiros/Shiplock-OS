import { describe, expect, it } from "vitest";
import { planFreshnessRechecks, type LatestRead } from "./freshness";

// Q11 / Step 9: accounts whose provider evidence is stale, failed, or partial
// get one extra recheck per day, oldest first, capped.
const now = Date.parse("2026-09-23T12:00:00.000Z");
const hoursAgo = (h: number) => new Date(now - h * 3_600_000).toISOString();
const read = (userId: string, observedAt: string, completeness: LatestRead["completeness"] = "complete",
  transport: LatestRead["transport"] = "supabase-management"): LatestRead => ({ userId, transport, observedAt, completeness });
const allConnected = () => true;

describe("planFreshnessRechecks", () => {
  it("picks stale, failed and partial reads and skips fresh complete ones", () => {
    const plan = planFreshnessRechecks([
      read("fresh", hoursAgo(2)), read("stale", hoursAgo(80)), read("failed", hoursAgo(1), "failed"), read("partial", hoursAgo(1), "partial"),
    ], allConnected, now);
    expect(plan.sort()).toEqual(["failed", "partial", "stale"]);
  });
  it("uses only each account and transport's newest read", () => {
    expect(planFreshnessRechecks([read("u", hoursAgo(100), "failed"), read("u", hoursAgo(1))], allConnected, now)).toEqual([]);
  });
  it("skips a provider that is no longer connected", () => {
    expect(planFreshnessRechecks([read("gone", hoursAgo(100))], () => false, now)).toEqual([]);
  });
  it("lists each account once, oldest evidence first, capped", () => {
    const rows = [read("b", hoursAgo(90)), read("a", hoursAgo(200)), read("a", hoursAgo(95), "complete", "vercel"), read("c", hoursAgo(75))];
    expect(planFreshnessRechecks(rows, allConnected, now)).toEqual(["a", "b", "c"]);
    expect(planFreshnessRechecks(rows, allConnected, now, 2)).toEqual(["a", "b"]);
  });
});

describe("admitFreshnessRechecks", () => {
  it("admits one pass per due account with an idempotent daily key, and skips disconnected ones", async () => {
    const { vi } = await import("vitest");
    const enqueue = vi.fn(async () => "job");
    vi.resetModules();
    vi.doMock("@/lib/jobs/scheduler", () => ({ enqueueMonitoringPass: enqueue }));
    const epoch = "a".repeat(64);
    vi.doMock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
      const q: Record<string, unknown> = {};
      Object.assign(q, { select: () => q, gte: () => q, order: () => q,
        limit: async () => ({ data: [
          { user_id: "11111111-1111-4111-8111-111111111111", transport: "vercel", observed_at: hoursAgo(90), completeness: "complete" },
          { user_id: "22222222-2222-4222-8222-222222222222", transport: "postgres-direct", observed_at: hoursAgo(1), completeness: "failed" },
        ], error: null }),
        in: async () => ({ data: table === "user_profiles" ? [
          { id: "11111111-1111-4111-8111-111111111111", vercel_access_token_encrypted: "c", vercel_connection_epoch: epoch },
          { id: "22222222-2222-4222-8222-222222222222", postgres_dsn_encrypted: null, postgres_connection_epoch: null },
        ] : [], error: null }) });
      return q;
    } }) }));
    const { admitFreshnessRechecks } = await import("./freshness");
    expect(await admitFreshnessRechecks(new Date(now))).toEqual({ admitted: 1, failed: 0 });
    expect(enqueue).toHaveBeenCalledWith("11111111-1111-4111-8111-111111111111", "scheduled_48h", "fresh:11111111-1111-4111-8111-111111111111:2026-09-23");
    vi.doUnmock("@/lib/supabase"); vi.doUnmock("@/lib/jobs/scheduler");
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ filters: [] as unknown[][], result: { data: [] as unknown, error: null as unknown } }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q = {
    select: () => q, order: () => q,
    eq: (...a: unknown[]) => { state.filters.push([table, "eq", ...a]); return q; },
    gte: (...a: unknown[]) => { state.filters.push([table, "gte", a[0]]); return q; },
    limit: async () => state.result,
  };
  return q;
} }) }));

import { getOpenedPullRequests } from "./openedPullRequests";

const row = (over: Record<string, unknown> = {}) => ({ id: "66666666-6666-4666-8666-666666666666", action: "finding-fix-pr",
  pr_url: "https://github.com/acme/app/pull/9", pr_number: 9, merged_at: null, requested_at: "2026-09-20T10:00:00.000Z",
  repositories: { full_name: "acme/app" }, ...over });

beforeEach(() => { state.filters = []; state.result = { data: [row()], error: null }; });

describe("getOpenedPullRequests", () => {
  it("lists only the caller's opened pull requests from the last 30 days", async () => {
    const result = await getOpenedPullRequests("u1");
    expect(result).toEqual({ available: true, items: [{ id: row().id, lane: "Fix", repository: "acme/app",
      number: 9, url: "https://github.com/acme/app/pull/9", mergedAt: null, requestedAt: "2026-09-20T10:00:00.000Z" }] });
    expect(state.filters).toContainEqual(["repair_action_receipts", "eq", "user_id", "u1"]);
    expect(state.filters).toContainEqual(["repair_action_receipts", "eq", "status", "opened"]);
    expect(state.filters).toContainEqual(["repair_action_receipts", "gte", "requested_at"]);
  });

  it("names each lane in plain words and carries the merge time", async () => {
    state.result = { data: [row({ action: "dependency-bump-pr" }), row({ action: "pr-fix-pr" }), row({ action: "ai-fix-pr", merged_at: "2026-09-23T12:00:00.000Z" }), row({ action: "risk-fix-pr" })], error: null };
    const { items } = await getOpenedPullRequests("u1");
    expect(items.map((i) => i.lane)).toEqual(["Dependency update", "Fix before merge", "Your AI's fix", "Fix"]);
    expect(items[2].mergedAt).toBe("2026-09-23T12:00:00.000Z");
  });

  it("fails soft and drops malformed rows", async () => {
    state.result = { data: null, error: { message: "down" } };
    expect(await getOpenedPullRequests("u1")).toEqual({ available: false, items: [] });
    state.result = { data: [row({ pr_url: "https://evil.example/pull/1" }), row()], error: null };
    expect((await getOpenedPullRequests("u1")).items).toHaveLength(1);
  });
});

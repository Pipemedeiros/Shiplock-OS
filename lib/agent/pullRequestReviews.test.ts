import { beforeEach, describe, expect, it, vi } from "vitest";

// The dashboard shows what each checked PR introduced, scoped to the
// signed-in account, and never invents a verdict from a malformed row.
const mocks = vi.hoisted(() => ({ read: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = {
    select: () => chain, order: () => chain, limit: mocks.read,
    eq: (k: string, v: unknown) => { mocks.filters(k, v); return chain; },
  };
  return chain;
} }) }));

import { getRecentPullRequestReviews } from "./pullRequestReviews";

const row = {
  id: "11111111-1111-4111-8111-111111111111", pull_request_number: 9, head_sha: "c".repeat(40),
  head_ref: "feature/orders", same_repository: true, title: "Add orders API", url: "https://github.com/acme/app/pull/9",
  verdict: "block", coverage_complete: true, checked_at: "2026-09-22T10:00:00.000Z",
  findings: [{ id: "diff:anon:/api/orders", severity: "CRITICAL", title: "Open route", detail: "d", file: "app/api/orders/route.ts", evidence: "e" }],
  repositories: { full_name: "acme/app" },
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.read.mockResolvedValue({ data: [row], error: null });
});

describe("getRecentPullRequestReviews", () => {
  it("returns the caller's recent reviews with findings and PR metadata", async () => {
    expect(await getRecentPullRequestReviews("u1")).toEqual([{
      id: row.id, repository: "acme/app", number: 9, headSha: "c".repeat(40), title: "Add orders API", url: row.url,
      headRef: "feature/orders", sameRepository: true, verdict: "block", coverageComplete: true,
      checkedAt: row.checked_at, findings: row.findings,
    }]);
    expect(mocks.filters).toHaveBeenCalledWith("user_id", "u1");
  });

  it("drops malformed rows instead of guessing a verdict", async () => {
    mocks.read.mockResolvedValue({ data: [row, { ...row, id: "bad", verdict: "clean" }], error: null });
    expect((await getRecentPullRequestReviews("u1")).map((r) => r.id)).toEqual([row.id]);
  });

  it("fails loudly when the read fails", async () => {
    mocks.read.mockResolvedValue({ data: null, error: { message: "down" } });
    await expect(getRecentPullRequestReviews("u1")).rejects.toThrow("could not be read");
  });
});

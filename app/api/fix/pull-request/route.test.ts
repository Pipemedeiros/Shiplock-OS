import { beforeEach, describe, expect, it, vi } from "vitest";

// 8B-3: the dashboard click that asks for a fix before the PR merges.
const mocks = vi.hoisted(() => ({ pro: vi.fn(), review: vi.fn(), request: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestRepairAction: mocks.request }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { select: () => chain, eq: (k: string, v: unknown) => { mocks.filters(k, v); return chain; }, maybeSingle: mocks.review };
  return chain;
} }) }));

import { POST } from "./route";

const reviewId = "77777777-7777-4777-8777-777777777777";
const post = (body: unknown) => POST(new Request("https://shiplock.dev/api/fix/pull-request", { method: "POST", headers: { origin: "https://shiplock.dev" }, body: JSON.stringify(body) }));
const repositoryId = "88888888-8888-4888-8888-888888888888";
const review = { repository_id: repositoryId, same_repository: true, head_ref: "feature/orders", findings: [{ id: "diff:x" }] };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.review.mockResolvedValue({ data: review, error: null });
  mocks.request.mockResolvedValue("receipt-1");
});

describe("POST /api/fix/pull-request", () => {
  it("admits a receipt bound to the caller's review and returns 202", async () => {
    const res = await post({ reviewId, findingId: "diff:x" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ receiptId: "receipt-1", status: "queued" });
    expect(mocks.filters).toHaveBeenCalledWith("user_id", "u1");
    expect(mocks.request).toHaveBeenCalledWith({ userId: "u1", repositoryId, action: "pr-fix-pr", findingId: "diff:x", editedContent: null, reviewId });
  });

  it.each([
    ["another tenant's or unknown review", () => mocks.review.mockResolvedValue({ data: null, error: null }), 404],
    ["a finding not in the review", () => mocks.review.mockResolvedValue({ data: { ...review, findings: [] }, error: null }), 404],
    ["a fork pull request", () => mocks.review.mockResolvedValue({ data: { ...review, same_repository: false }, error: null }), 409],
  ])("refuses %s before admitting anything", async (_name, arrange, status) => {
    arrange();
    expect((await post({ reviewId, findingId: "diff:x" })).status).toBe(status);
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it("rejects a malformed body and requires sign in", async () => {
    expect((await post({ reviewId: "nope", findingId: "diff:x" })).status).toBe(400);
    mocks.pro.mockResolvedValue(null);
    expect((await post({ reviewId, findingId: "diff:x" })).status).toBe(401);
  });
});

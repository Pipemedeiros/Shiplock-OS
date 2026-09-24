import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), read: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { eq: (k: string, v: unknown) => { mocks.filters(k, v); return chain; }, maybeSingle: mocks.read };
  return { select: () => chain };
} }) }));

import { GET } from "./route";

const id = "66666666-6666-4666-8666-666666666666";
const get = (receiptId = id) => GET(new Request(`https://shiplock.dev/api/fix/receipts/${receiptId}`), { params: Promise.resolve({ id: receiptId }) });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.read.mockResolvedValue({ data: { status: "opened", pr_url: "https://github.com/acme/app/pull/9", failure_code: null, merged_at: null }, error: null });
});

describe("GET /api/fix/receipts/[id] (3F-C2d-3)", () => {
  it("returns the caller's own receipt status, scoped by user", async () => {
    const res = await get();
    expect(await res.json()).toEqual({ status: "opened", url: "https://github.com/acme/app/pull/9", failure: null, mergedAt: null });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(mocks.filters).toHaveBeenCalledWith("user_id", "u1");
    expect(mocks.filters).toHaveBeenCalledWith("id", id);
  });

  it("says when the customer merged the pull request (Q1 / 8-R2)", async () => {
    mocks.read.mockResolvedValue({ data: { status: "opened", pr_url: "https://github.com/acme/app/pull/9", failure_code: null, merged_at: "2026-09-23T12:00:00.000Z" }, error: null });
    expect(await (await get()).json()).toMatchObject({ mergedAt: "2026-09-23T12:00:00.000Z" });
  });

  it("returns 404 for another tenant's or unknown receipt", async () => {
    mocks.read.mockResolvedValue({ data: null, error: null });
    expect((await get()).status).toBe(404);
  });

  it("rejects a malformed id before reading", async () => {
    expect((await get("not-a-uuid")).status).toBe(400);
    expect(mocks.read).not.toHaveBeenCalled();
  });

  it("requires a signed-in account", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await get()).status).toBe(401);
  });
});

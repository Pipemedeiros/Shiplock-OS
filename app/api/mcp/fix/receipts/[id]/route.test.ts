import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// The agent follows the PR it asked for (103): only the token owner's receipt.
const mocks = vi.hoisted(() => ({ auth: vi.fn(), row: vi.fn(), eq: vi.fn() }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: mocks.auth }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { eq: (...a: unknown[]) => { mocks.eq(...a); return chain; }, maybeSingle: mocks.row };
  return { select: () => chain };
} }) }));

import { GET } from "./route";

const ID = "66666666-6666-4666-8666-666666666666";
const get = (id: string) => GET(new NextRequest(`https://shiplock.dev/api/mcp/fix/receipts/${id}`), { params: Promise.resolve({ id }) });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.auth.mockResolvedValue({ userId: "u1" });
  mocks.row.mockResolvedValue({ data: { status: "opened", pr_url: "https://github.com/a/b/pull/3", failure_code: null, merged_at: null }, error: null });
});

describe("GET /api/mcp/fix/receipts/[id]", () => {
  it("returns the outcome of the token owner's own receipt", async () => {
    const res = await get(ID);
    expect(await res.json()).toEqual({ status: "opened", url: "https://github.com/a/b/pull/3", failure: null, mergedAt: null });
    expect(mocks.eq).toHaveBeenCalledWith("user_id", "u1");
  });
  it("refuses a malformed id and an unknown receipt", async () => {
    expect((await get("../x")).status).toBe(400);
    mocks.row.mockResolvedValue({ data: null, error: null });
    expect((await get(ID)).status).toBe(404);
  });
});

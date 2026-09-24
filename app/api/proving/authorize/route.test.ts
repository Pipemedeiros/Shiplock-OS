import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), rpc: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));

import { POST } from "./route";

const repositoryId = "33333333-3333-4333-8333-333333333333";
const authId = "66666666-6666-4666-8666-666666666666";
const post = (body: unknown, origin = "https://shiplock.dev") => POST(new Request("https://shiplock.dev/api/proving/authorize", {
  method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body),
}));
const valid = { repositoryId, findingId: "policy:public.orders:read:unrestricted_read", table: "public.orders", key: "click-1" };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.rpc.mockResolvedValue({ data: authId, error: null });
});

describe("POST /api/proving/authorize (Q5 / 6A-1)", () => {
  it("refuses a cross-site request before anything else", async () => {
    expect((await post(valid, "https://evil.example")).status).toBe(403);
    expect(mocks.pro).not.toHaveBeenCalled();
  });
  it("requires a signed-in account", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await post(valid)).status).toBe(401);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it("rejects a malformed body before any write", async () => {
    for (const body of [{}, { ...valid, table: "orders" }, { ...valid, repositoryId: "x" }, { ...valid, extra: 1 }, { ...valid, key: "" }]) {
      expect((await post(body)).status).toBe(400);
    }
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it("issues one authorization for the caller, idempotently by key", async () => {
    const res = await post(valid);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ authorizationId: authId });
    expect(mocks.rpc).toHaveBeenCalledWith("authorize_proof", {
      p_user: "u1", p_repository: repositoryId, p_finding: valid.findingId, p_table: "public.orders", p_key: "click-1",
    });
  });
  it.each([
    ["idempotency key reused", 409], ["repository unavailable", 404], ["too many outstanding proofs", 429], ["something else", 503],
  ])("maps %s to %i", async (message, status) => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message } });
    expect((await post(valid)).status).toBe(status);
  });
});

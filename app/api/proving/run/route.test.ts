import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), rpc: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc: mocks.rpc }) }));

import { POST } from "./route";

const authorizationId = "66666666-6666-4666-8666-666666666666";
const jobId = "77777777-7777-4777-8777-777777777777";
const post = (body: unknown, origin = "https://shiplock.dev") => POST(new Request("https://shiplock.dev/api/proving/run", {
  method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body),
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.rpc.mockResolvedValue({ data: jobId, error: null });
});

describe("POST /api/proving/run (Q7 / 6A-3)", () => {
  it("refuses a cross-site request before anything else", async () => {
    expect((await post({ authorizationId }, "https://evil.example")).status).toBe(403);
    expect(mocks.pro).not.toHaveBeenCalled();
  });
  it("requires a signed-in account", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await post({ authorizationId })).status).toBe(401);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it("rejects a malformed body before any write", async () => {
    for (const body of [{}, { authorizationId: "x" }, { authorizationId, extra: 1 }]) expect((await post(body)).status).toBe(400);
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
  it("consumes the caller's own authorization and queues one proof job", async () => {
    const res = await post({ authorizationId });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jobId });
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(mocks.rpc).toHaveBeenCalledExactlyOnceWith("enqueue_proof_job", { p_user: "u1", p_authorization: authorizationId });
  });
  it("says an unknown, expired, used or someone else's authorization is unavailable", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "proof authorization unavailable" } });
    const res = await post({ authorizationId });
    expect(res.status).toBe(404);
    expect((await res.json()).error).not.toMatch(/[–—]/);
  });
  it("maps any other failure to a retryable 503", async () => {
    mocks.rpc.mockResolvedValue({ data: null, error: { message: "boom" } });
    expect((await post({ authorizationId })).status).toBe(503);
  });
});

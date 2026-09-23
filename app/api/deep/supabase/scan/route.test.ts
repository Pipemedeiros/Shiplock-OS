import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), recheck: vi.fn(), scan: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/jobs/manualRecheck", () => ({ queueCustomerRecheck: mocks.recheck }));
vi.mock("@/lib/deep/supabaseMgmtRun", () => ({ runPolicyScan: mocks.scan }));

import { POST } from "./route";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.recheck.mockResolvedValue("job-1");
});

describe("POST /api/deep/supabase/scan (3F-C2c-5)", () => {
  it("queues a durable recheck instead of collecting in the request", async () => {
    const res = await POST(new Request("https://shiplock.dev/api/deep/supabase/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ ok: true, status: "queued" });
    expect(mocks.recheck).toHaveBeenCalledWith("u1", "supabase-management");
    expect(mocks.scan).not.toHaveBeenCalled();
  });

  it("reports a recheck that could not be admitted", async () => {
    mocks.recheck.mockRejectedValue(new Error("Monitoring could not be queued"));
    expect((await POST(new Request("https://shiplock.dev/api/deep/supabase/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }))).status).toBe(409);
  });

  it("still requires access", async () => {
    mocks.pro.mockResolvedValue(null);
    expect((await POST(new Request("https://shiplock.dev/api/deep/supabase/scan", { method: "POST", headers: { origin: "https://shiplock.dev" } }))).status).toBe(402);
    expect(mocks.recheck).not.toHaveBeenCalled();
  });
});

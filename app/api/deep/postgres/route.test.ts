import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), recheck: vi.fn(), connect: vi.fn(), disconnect: vi.fn(), scan: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/jobs/manualRecheck", () => ({ queueCustomerRecheck: mocks.recheck }));
vi.mock("@/lib/deep/postgresDirectRun", () => ({
  connectDirectPostgres: mocks.connect, disconnectDirectPostgres: mocks.disconnect, runDirectPostgresScan: mocks.scan,
}));

import { POST } from "./route";

const post = (body: unknown) => POST(new Request("https://shiplock.dev/api/deep/postgres", { method: "POST", body: JSON.stringify(body) }));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.recheck.mockResolvedValue("job-1");
  mocks.connect.mockResolvedValue({ ok: true, display: "db.example.com/app" });
});

describe("POST /api/deep/postgres (3F-C2c-5)", () => {
  it("queues a recheck for the scan action", async () => {
    const res = await post({ action: "scan" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ ok: true, status: "queued" });
    expect(mocks.recheck).toHaveBeenCalledWith("u1", "postgres-direct");
    expect(mocks.scan).not.toHaveBeenCalled();
  });

  it("connects, then queues the first read instead of running it in the request", async () => {
    const res = await post({ action: "connect", connectionString: "postgres://r:s@db.example.com/app" });
    expect(await res.json()).toEqual({ ok: true, display: "db.example.com/app", status: "queued" });
    expect(mocks.recheck).toHaveBeenCalledWith("u1", "postgres-direct");
    expect(mocks.scan).not.toHaveBeenCalled();
  });

  it("keeps a successful connection even when the first read cannot be queued", async () => {
    mocks.recheck.mockRejectedValue(new Error("Monitoring could not be queued"));
    const res = await post({ action: "connect", connectionString: "postgres://r:s@db.example.com/app" });
    expect(await res.json()).toEqual({ ok: true, display: "db.example.com/app", status: "not_queued" });
  });
});

import { describe, expect, it, vi } from "vitest";
import { runWorkerCycle, workerEndpoints } from "./worker-client.mjs";

const response = (body: unknown, status = 200) => ({
  status,
  ok: status >= 200 && status < 300,
  json: async () => body,
});

describe("durable worker client", () => {
  it("keeps credentials in headers and runs admission before execution", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ admitted: 1, failed: 0, more: true }))
      .mockResolvedValueOnce(response({ processed: 1 }));
    await expect(runWorkerCycle({
      baseUrl: "https://shiplock.test",
      secret: "worker-secret",
      schedule: true,
      fetchImpl: fetchMock,
    })).resolves.toEqual({ processed: true, scheduleMore: true });
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "https://shiplock.test/api/jobs/schedule",
      "https://shiplock.test/api/jobs/drain",
    ]);
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("worker-secret");
    expect(fetchMock.mock.calls[0][1].headers).toEqual({ authorization: "Bearer worker-secret" });
  });

  it("can drain without scheduling and rejects authorization failures", async () => {
    const drain = vi.fn().mockResolvedValue(response({ processed: 0 }));
    await expect(runWorkerCycle({ baseUrl: "http://localhost:3000", secret: "x", schedule: false, fetchImpl: drain }))
      .resolves.toEqual({ processed: false, scheduleMore: false });
    expect(drain).toHaveBeenCalledOnce();

    const denied = vi.fn().mockResolvedValue(response({}, 401));
    await expect(runWorkerCycle({ baseUrl: "https://shiplock.test", secret: "x", schedule: false, fetchImpl: denied }))
      .rejects.toThrow("authorization");
  });

  it("constructs fixed same-origin worker endpoints", () => {
    expect(Object.values(workerEndpoints("https://shiplock.test")).map(String)).toEqual([
      "https://shiplock.test/api/jobs/drain",
      "https://shiplock.test/api/jobs/schedule",
    ]);
  });
});

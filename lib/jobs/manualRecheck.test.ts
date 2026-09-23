import { beforeEach, describe, expect, it, vi } from "vitest";

// 3F-C2c-5: a dashboard "check now" admits a durable monitor job instead of
// collecting inside the web request.
const mocks = vi.hoisted(() => ({ enqueue: vi.fn(), after: vi.fn(), run: vi.fn() }));
vi.mock("next/server", async (original) => ({ ...(await original<typeof import("next/server")>()), after: mocks.after }));
vi.mock("./scheduler", () => ({ enqueueMonitoringPass: mocks.enqueue }));
vi.mock("./monitorWorker", () => ({ runNextMonitorJob: mocks.run }));

import { queueCustomerRecheck } from "./manualRecheck";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.enqueue.mockResolvedValue("job-1");
  vi.useFakeTimers({ now: new Date("2026-09-22T10:15:42.000Z"), toFake: ["Date"] });
});

describe("queueCustomerRecheck", () => {
  it("admits one manual monitor job per transport per minute and wakes a worker", async () => {
    expect(await queueCustomerRecheck("user-1", "postgres-direct")).toBe("job-1");
    expect(mocks.enqueue).toHaveBeenCalledWith("user-1", "manual", "manual:postgres-direct:2026-09-22T10:15");
    expect(mocks.after).toHaveBeenCalledOnce();
    await mocks.after.mock.calls[0][0]();
    expect(mocks.run).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });

  it("propagates an admission failure", async () => {
    mocks.enqueue.mockRejectedValue(new Error("Monitoring could not be queued"));
    await expect(queueCustomerRecheck("user-1", "vercel")).rejects.toThrow("could not be queued");
    expect(mocks.after).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

const runNextJob = vi.hoisted(() => vi.fn());
vi.mock("@/lib/jobs/worker", () => ({ runNextJob }));

import { POST } from "./route";

function request(secret?: string) {
  return new Request("https://shiplock.dev/api/jobs/drain", {
    method: "POST",
    headers: secret ? { authorization: `Bearer ${secret}` } : undefined,
  });
}

describe("POST /api/jobs/drain", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("CRON_SECRET", "worker-secret");
    runNextJob.mockResolvedValue(false);
  });

  it("refuses missing and incorrect worker credentials before claiming", async () => {
    expect((await POST(request())).status).toBe(401);
    expect((await POST(request("wrong"))).status).toBe(401);
    expect(runNextJob).not.toHaveBeenCalled();
  });

  it("runs one bounded claim and reports whether work was processed", async () => {
    runNextJob.mockResolvedValueOnce(true).mockResolvedValueOnce(false);

    const worked = await POST(request("worker-secret"));
    expect(worked.status).toBe(200);
    await expect(worked.json()).resolves.toEqual({ processed: 1 });

    const idle = await POST(request("worker-secret"));
    await expect(idle.json()).resolves.toEqual({ processed: 0 });
    expect(runNextJob).toHaveBeenCalledTimes(2);
  });

  it("returns a generic failure while the claimed job owns retry state", async () => {
    runNextJob.mockRejectedValue(new Error("private provider detail"));
    const response = await POST(request("worker-secret"));
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({ error: "Worker invocation failed." });
  });
});

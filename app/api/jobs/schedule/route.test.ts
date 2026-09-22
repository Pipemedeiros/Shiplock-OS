import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({audits:vi.fn(),sources:vi.fn()}));
vi.mock("@/lib/jobs/scheduler", () => ({ admitDueRepositoryAudits: mocks.audits,admitDueRepositorySourceScans:mocks.sources }));
import { POST } from "./route";

const request = (secret?: string) => new Request("https://shiplock.dev/api/jobs/schedule", {
  method: "POST",
  headers: secret ? { authorization: `Bearer ${secret}` } : undefined,
});

describe("POST /api/jobs/schedule", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("CRON_SECRET", "worker-secret");
    mocks.audits.mockResolvedValue({ eligible: 4, admitted: 3, failed: 1, limited: true });
    mocks.sources.mockResolvedValue({eligible:2,admitted:2,failed:0,limited:false});
  });

  it("authenticates before admitting a bounded batch", async () => {
    expect((await POST(request("wrong"))).status).toBe(401);
    expect(mocks.audits).not.toHaveBeenCalled();
    const response = await POST(request("worker-secret"));
    await expect(response.json()).resolves.toEqual({ admitted: 5, failed: 1, more: true });
  });

  it("returns no tenant details when admission fails", async () => {
    mocks.sources.mockRejectedValue(new Error("private detail"));
    const response = await POST(request("worker-secret"));
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({ error: "Scheduler invocation failed." });
  });
});

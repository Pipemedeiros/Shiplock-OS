import { afterEach, describe, expect, it, vi } from "vitest";
import { isAuthorizedWorkerRequest } from "./workerAuth";

afterEach(() => vi.unstubAllEnvs());

function request(authorization?: string) {
  return new Request("https://shiplock.dev/api/jobs/drain", {
    method: "POST",
    headers: authorization ? { authorization } : undefined,
  });
}

describe("worker wake authentication", () => {
  it("fails closed when the server secret or bearer token is absent", () => {
    vi.stubEnv("CRON_SECRET", "");
    expect(isAuthorizedWorkerRequest(request("Bearer secret"))).toBe(false);
    vi.stubEnv("CRON_SECRET", "secret");
    expect(isAuthorizedWorkerRequest(request())).toBe(false);
  });

  it("accepts only an exact bearer secret", () => {
    vi.stubEnv("CRON_SECRET", "worker-secret");
    expect(isAuthorizedWorkerRequest(request("Bearer worker-secret"))).toBe(true);
    expect(isAuthorizedWorkerRequest(request("Bearer wrong-secret"))).toBe(false);
    expect(isAuthorizedWorkerRequest(request("Basic worker-secret"))).toBe(false);
  });
});

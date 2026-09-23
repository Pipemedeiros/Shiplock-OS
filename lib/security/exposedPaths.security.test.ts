import { describe, expect, it, vi, beforeEach } from "vitest";

const assertPublicHttpsUrlMock = vi.fn();
vi.mock("@/lib/security/ssrfGuard", () => ({ assertPublicHttpsUrl: assertPublicHttpsUrlMock }));

const { probeExposedPaths } = await import("./exposedPaths");

describe("probeExposedPaths — SSRF guard integration", () => {
  beforeEach(() => {
    assertPublicHttpsUrlMock.mockReset();
    vi.unstubAllGlobals();
  });

  it("never issues a single probe request when the host resolves privately", async () => {
    assertPublicHttpsUrlMock.mockRejectedValue(new Error("blocked: private address"));
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await probeExposedPaths("https://internal-service.attacker.example/");

    expect(result).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("probes normally once the host clears the guard", async () => {
    assertPublicHttpsUrlMock.mockResolvedValue(undefined);
    const fetchMock = vi.fn(async () => new Response("not a git repo", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);

    await probeExposedPaths("https://app.example.com/");

    expect(fetchMock).toHaveBeenCalled();
  });
});

describe("probeExposedPaths — 3F-C2b-2 cancellation", () => {
  it("aborts every in-flight probe when the caller aborts", async () => {
    assertPublicHttpsUrlMock.mockResolvedValue(undefined);
    const signals: AbortSignal[] = [];
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal);
      return new Promise<Response>(() => {});
    }));
    const caller = new AbortController();
    void probeExposedPaths("https://app.example.com/", caller.signal);
    await vi.waitFor(() => expect(signals.length).toBeGreaterThan(0));
    caller.abort(new Error("collector timed out"));
    expect(signals.every((s) => s.aborted)).toBe(true);
    vi.unstubAllGlobals();
  });
});

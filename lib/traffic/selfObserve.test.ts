import { beforeEach, describe, expect, it, vi } from "vitest";

// Felipe (2026-10-01): dogfood traffic. ShipLock records its own page requests
// to his traffic site for shiplock.dev, after the response, never blocking,
// with the same minimised fields the customer snippet sends.
const s = vi.hoisted(() => ({ ingest: vi.fn(), site: vi.fn() }));
vi.mock("@/lib/traffic/ingest", () => ({ ingestTrafficEvent: s.ingest }));
vi.mock("@/lib/traffic/sites", () => ({ resolveTrafficSiteById: s.site }));
import { observeSelf, resetSelfSiteCache, shouldObserve, visitorId } from "./selfObserve";

const req = (path: string, headers: Record<string, string> = {}) => new Request(`https://shiplock.dev${path}`, {
  headers: { "user-agent": "Mozilla/5.0", "x-forwarded-for": "203.0.113.7", ...headers },
});
const identity = { userId: "u1", email: "f@x.co", siteId: "site-1", repositoryId: "r1" };

beforeEach(() => { vi.clearAllMocks(); resetSelfSiteCache(); s.site.mockResolvedValue(identity); s.ingest.mockResolvedValue({ action: "none" }); });

describe("which requests count", () => {
  it("counts page and API requests, not prefetches, assets, health or traffic plumbing", () => {
    expect(shouldObserve(req("/dashboard"))).toBe(true);
    expect(shouldObserve(req("/api/audit"))).toBe(true);
    expect(shouldObserve(req("/dashboard", { "next-router-prefetch": "1" }))).toBe(false);
    expect(shouldObserve(req("/dashboard", { purpose: "prefetch" }))).toBe(false);
    for (const p of ["/api/traffic/ingest", "/api/health", "/_next/data/x.json", "/robots.txt", "/llms.txt", "/apple-icon.png"]) {
      expect(shouldObserve(req(p)), p).toBe(false);
    }
  });
});

describe("observeSelf", () => {
  it("records path, method, user agent and a hashed visitor, never the address or query", async () => {
    await observeSelf(req("/dashboard/risks?token=secret"), "site-1");
    const event = s.ingest.mock.calls[0][0];
    expect(event).toMatchObject({ userId: "u1", siteId: "site-1", repositoryId: "r1" });
    expect(event.event).toMatchObject({ path: "/dashboard/risks", method: "GET", ua: "Mozilla/5.0" });
    expect(JSON.stringify(event)).not.toMatch(/203\.0\.113\.7|secret/);
    expect(event.event.source_id).toBe(await visitorId("203.0.113.7", "site-1"));
  });

  it("does nothing without a configured or valid site, and never throws", async () => {
    await observeSelf(req("/dashboard"), "");
    s.site.mockResolvedValue(null);
    await observeSelf(req("/dashboard"), "site-1");
    expect(s.ingest).not.toHaveBeenCalled();
    s.site.mockRejectedValue(new Error("db down"));
    resetSelfSiteCache();
    await expect(observeSelf(req("/dashboard"), "site-1")).resolves.toBeUndefined();
  });

  it("looks the site up once per instance window, not on every request", async () => {
    await observeSelf(req("/a"), "site-1");
    await observeSelf(req("/b"), "site-1");
    expect(s.site).toHaveBeenCalledTimes(1);
  });
});
